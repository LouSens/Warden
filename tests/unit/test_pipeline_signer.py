"""Firewall pipeline (D3, no chain) and signer refusals, against temp SQLite databases."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path

import pytest
from _fw import (
    ACME,
    AMM,
    ATTACKER,
    MAX,
    NOW,
    TUSD,
    USER,
    approve,
    mandate,
    registries,
    transfer,
    tx,
)

from warden.clock import FixedClock
from warden.firewall.models import Origin, Proposal, ProposalKind, Verdict
from warden.firewall.pipeline import CONFIGS, ApprovalResolved, Firewall
from warden.firewall.store import FirewallStore
from warden.policy.evaluator import load_policy
from warden.secrets import ANVIL_USER_KEY
from warden.signer.core import Signer, SignerRefused, recover_typed
from warden.storage.database import Database
from warden.storage.migrate import migrate
from warden.tokens import mint

SECRET = b"k" * 32


@pytest.fixture
async def fw(tmp_path: Path) -> AsyncIterator[tuple[Firewall, str, FixedClock]]:
    db = await Database(tmp_path / "w.db").open()
    await migrate(db, "warden")
    store = FirewallStore(db)
    clock = FixedClock(NOW)
    firewall = Firewall(
        store=store,
        policy=load_policy(Path("policy.yaml").read_text()),
        registries=registries(),
        clock=clock,
        token_secret=SECRET,
        config=CONFIGS["D3"],
    )
    mid = await store.insert_mandate(mandate(), prompt_sha256="p", now=NOW)
    sid = await store.create_session(mid, NOW)
    yield firewall, sid, clock
    await db.close()


async def test_allow_mints_token_and_records_chain(fw: tuple[Firewall, str, FixedClock]) -> None:
    firewall, sid, _ = fw
    d = await firewall.evaluate(sid, transfer(TUSD, ACME, 120_000_000), origin=Origin.AGENT)
    assert d.verdict is Verdict.ALLOW and d.decision_token and d.mandate_satisfied
    assert "decision_token" not in d.for_agent()
    assert (await firewall.store.verify_chain())["ok"]


async def test_redirect_and_unlimited_approval_block(fw: tuple[Firewall, str, FixedClock]) -> None:
    firewall, sid, _ = fw
    d = await firewall.evaluate(sid, transfer(TUSD, ATTACKER, 120_000_000))
    assert d.verdict is Verdict.BLOCK and d.decision_token is None
    assert "recipient_not_in_mandate" in {f.code for f in d.findings}
    d2 = await firewall.evaluate(sid, approve(TUSD, AMM, MAX))
    assert d2.verdict is Verdict.BLOCK and "unlimited-approval" in d2.matched_rules


async def test_session_cap_accumulates(fw: tuple[Firewall, str, FixedClock]) -> None:
    firewall, sid, _ = fw
    for _ in range(2):
        assert (
            await firewall.evaluate(sid, transfer(TUSD, ACME, 140_000_000))
        ).verdict is Verdict.ALLOW
    third = await firewall.evaluate(sid, transfer(TUSD, ACME, 30_000_000))
    assert third.verdict is Verdict.BLOCK and "session_cap" in {f.code for f in third.findings}


async def test_escalation_approve_deny_and_timeout(fw: tuple[Firewall, str, FixedClock]) -> None:
    firewall, sid, clock = fw
    unknown = tx(TUSD, "0xdeadbeef")
    esc = await firewall.evaluate(sid, unknown)
    assert esc.verdict is Verdict.ESCALATE and esc.approval_id
    ok = await firewall.resolve_approval(esc.approval_id, approve=True, note="I checked it")
    assert ok.verdict is Verdict.ALLOW and ok.decision_token
    with pytest.raises(ApprovalResolved):
        await firewall.resolve_approval(esc.approval_id, approve=False)

    esc2 = await firewall.evaluate(sid, unknown)
    denied = await firewall.resolve_approval(esc2.approval_id or "", approve=False)
    assert denied.verdict is Verdict.BLOCK

    esc3 = await firewall.evaluate(sid, unknown)
    clock.advance(601)
    expired = await firewall.expire_approvals()
    assert [d.verdict for d in expired] == [Verdict.BLOCK]
    assert expired[0].decided_by.value == "timeout" and esc3.approval_id
    assert (await firewall.store.verify_chain())["ok"]


async def test_tampering_is_detected(fw: tuple[Firewall, str, FixedClock]) -> None:
    firewall, sid, _ = fw
    for amount in (1, 2, 3):
        await firewall.evaluate(sid, transfer(TUSD, ACME, amount))
    db = firewall.store.db
    await db.execute("DROP TRIGGER decision_no_update")
    await db.execute("UPDATE decision SET verdict='block' WHERE seq=2")
    report = await firewall.store.verify_chain()
    assert report == {"ok": False, "rows_checked": 2, "first_bad_row": report["first_bad_row"]}


# ---------------------------------------------------------------- signer (no chain needed)


@pytest.fixture
async def signer(tmp_path: Path) -> AsyncIterator[Signer]:
    db = await Database(tmp_path / "s.db").open()
    await migrate(db, "signer")
    s = Signer(
        key=ANVIL_USER_KEY,
        token_secret=SECRET,
        db=db,
        rpc=None,  # type: ignore[arg-type]
        clock=FixedClock(NOW),
        max_native_wei=10**18,
        max_token_amount=10**24,
    )
    yield s
    await db.close()


def _typed() -> Proposal:
    td = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "Note": [{"name": "text", "type": "string"}],
        },
        "primaryType": "Note",
        "domain": {"name": "Test", "chainId": 31337},
        "message": {"text": "hello"},
    }
    return Proposal(
        kind=ProposalKind.TYPED_DATA, chain_id=31337, payload={"from": USER, "typed_data": td}
    )


def _token(p: Proposal, *, chain_id: int = 31337, ttl: int = 120, secret: bytes = SECRET) -> str:
    from warden.canonical import canonical_sha256

    token, _ = mint(
        secret,
        decision_id="dec_x",
        proposal_sha256=canonical_sha256(p.model_dump(mode="json")),
        chain_id=chain_id,
        expires_at=NOW + timedelta(seconds=ttl),
    )
    return token


async def test_signer_signs_once(signer: Signer) -> None:
    p = _typed()
    token = _token(p)
    out = await signer.sign(token, p)
    assert out.signature and recover_typed(out.signature, p.payload["typed_data"]) == USER
    with pytest.raises(SignerRefused, match="reused"):
        await signer.sign(token, p)


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        (lambda p: (_token(p, secret=b"forged" * 6), p), "bad_mac"),
        (lambda p: (_token(p, ttl=-1), p), "expired"),
        (lambda p: (_token(p), transfer(TUSD, ACME, 1)), "hash_mismatch"),
        (lambda p: (_token(p, chain_id=1), p), "chain"),
    ],
)
async def test_signer_refusals(signer: Signer, make: object, reason: str) -> None:
    token, proposal = make(_typed())  # type: ignore[operator]
    with pytest.raises(SignerRefused) as info:
        await signer.sign(token, proposal)
    assert info.value.reason == reason


@pytest.mark.parametrize("chain_id", [1, 8453, 10, 42161, 137])
async def test_signer_refuses_mainnet_even_with_valid_mac(signer: Signer, chain_id: int) -> None:
    p = Proposal(kind=ProposalKind.TYPED_DATA, chain_id=chain_id, payload=_typed().payload)
    with pytest.raises(SignerRefused) as info:
        await signer.sign(_token(p, chain_id=chain_id), p)
    assert info.value.reason == "chain"


async def test_signer_refuses_other_senders_and_ceilings(signer: Signer) -> None:
    other = Proposal(
        kind=ProposalKind.TYPED_DATA, chain_id=31337, payload={**_typed().payload, "from": ACME}
    )
    with pytest.raises(SignerRefused):
        await signer.sign(_token(other), other)
    big = tx(ACME, value=2 * 10**18)
    with pytest.raises(SignerRefused) as info:
        await signer.sign(_token(big), big)
    assert info.value.reason == "ceiling"
