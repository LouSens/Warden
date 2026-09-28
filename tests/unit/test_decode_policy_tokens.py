from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from _fw import (
    ACME,
    AMM,
    NOW,
    SWEEPER,
    TDAI,
    TGOV,
    TUSD,
    USER,
    WEATHER,
    approve,
    calldata,
    permit_typed,
    registries,
    swap,
    transfer,
    tx,
    x402,
)

from warden.checks.context import BookEntry
from warden.decode.decoder import CallDecoder
from warden.firewall.models import ActionKind, Finding, Proposal, ProposalKind, Severity, Verdict
from warden.mandate.resolver import DraftCap, DraftRecipient, MandateDraft, MandateResolver
from warden.policy.evaluator import PolicyInput, PolicyInvalid, evaluate, load_policy
from warden.tokens import TokenError, mint, verify

D = CallDecoder()

# ---------------------------------------------------------------- decoder


def test_decode_transfer_approve_swap() -> None:
    a = D.decode(transfer(TUSD, ACME, 5))
    assert (a.kind, a.token, a.to, a.amount) == (ActionKind.TRANSFER, TUSD, ACME, 5)
    b = D.decode(approve(TDAI, AMM, 9))
    assert (b.kind, b.spender, b.owner) == (ActionKind.APPROVE, AMM, USER)
    c = D.decode(swap(TUSD, TGOV, 3))
    assert (c.kind, c.token_in, c.token_out, c.amount_in, c.to) == (
        ActionKind.SWAP,
        TUSD,
        TGOV,
        3,
        USER,
    )


def test_decode_multicall_recurses() -> None:
    inner = [bytes.fromhex(swap(TUSD, TGOV, 1).payload["data"][2:]), bytes.fromhex("deadbeef")]
    data = calldata("multicall(bytes[])", ["bytes[]"], [inner])
    a = D.decode(tx(AMM, data))
    assert a.kind is ActionKind.BATCH
    assert [leaf.kind for leaf in a.leaves()] == [ActionKind.SWAP, ActionKind.UNKNOWN]


def test_authorization_list_always_decoded() -> None:
    p = transfer(TUSD, ACME, 1)
    p = Proposal(
        kind=p.kind,
        chain_id=p.chain_id,
        payload={**p.payload, "authorization_list": [{"address": SWEEPER}]},
    )
    kinds = [leaf.kind for leaf in D.decode(p).leaves()]
    assert kinds == [ActionKind.DELEGATE, ActionKind.TRANSFER]


def test_native_value_and_typed_data_and_x402() -> None:
    assert D.decode(tx(ACME, value=10)).kind is ActionKind.TRANSFER
    p = D.decode(permit_typed(AMM, 7, 99))
    assert (p.kind, p.spender, p.amount, p.deadline) == (ActionKind.PERMIT, AMM, 7, 99)
    x = D.decode(x402())
    assert (x.kind, x.to, x.service) == (ActionKind.X402, WEATHER, "weather-api")


def test_unknown_and_malformed_become_unknown() -> None:
    assert D.decode(tx(TUSD, "0xdeadbeef")).kind is ActionKind.UNKNOWN
    assert D.decode(tx(TUSD, "0xa9059cbb00")).kind is ActionKind.UNKNOWN  # truncated args
    bad = Proposal(kind=ProposalKind.TYPED_DATA, chain_id=31337, payload={"from": USER})
    assert D.decode(bad).kind is ActionKind.UNKNOWN


# ---------------------------------------------------------------- policy

POLICY = Path("policy.yaml").read_text(encoding="utf-8")


def _f(code: str, sev: Severity = Severity.HIGH) -> Finding:
    return Finding(code=code, severity=sev)


def _eval(findings: list[Finding], satisfied: bool, usd: str | None = "10") -> Verdict:
    from decimal import Decimal

    lp = load_policy(POLICY)
    return evaluate(
        lp.policy,
        PolicyInput(
            findings,
            satisfied,
            Decimal(usd) if usd is not None else None,
            {ActionKind.TRANSFER},
            31337,
        ),
    ).verdict


def test_default_policy_is_valid() -> None:
    lp = load_policy(POLICY)
    assert lp.policy.defaults.verdict is Verdict.BLOCK and len(lp.sha256) == 64


def test_policy_precedence_and_default_deny() -> None:
    assert _eval([], True) is Verdict.ALLOW
    assert _eval([], False) is Verdict.BLOCK  # nothing allows it: default deny
    assert _eval([_f("first_seen_recipient", Severity.LOW)], True) is Verdict.ESCALATE
    assert (
        _eval([_f("first_seen_recipient", Severity.LOW), _f("lookalike_recipient")], False)
        is Verdict.BLOCK
    )
    assert _eval([], True, usd="1001") is Verdict.ESCALATE
    assert _eval([], True, usd=None) is Verdict.ESCALATE  # no trusted price: treat as over


@pytest.mark.parametrize(
    ("snippet", "error"),
    [
        (
            "defaults: {verdict: allow}\nrules: [{id: a, when: {finding: chain_mismatch}, then: block}]",
            "default deny",
        ),
        ("rules: [{id: a, when: {findings_max_severity: low}, then: allow}]", "mandate_satisfied"),
        ("rules: [{id: a, when: {finding: made_up}, then: block}]", "unknown check code"),
        (
            "rules: [{id: a, when: {finding: chain_mismatch}, then: block},\n"
            "        {id: a, when: {finding: chain_mismatch}, then: block}]",
            "duplicate",
        ),
        ("rules: [{id: a, when: {amount_over: nope}, then: escalate}]", "unknown limit"),
    ],
)
def test_invalid_policies_rejected(snippet: str, error: str) -> None:
    with pytest.raises(PolicyInvalid, match=error):
        load_policy("version: 1\n" + snippet)


# ---------------------------------------------------------------- tokens


def test_token_roundtrip_and_refusals() -> None:
    secret = b"s" * 32
    token, payload = mint(
        secret,
        decision_id="dec_1",
        proposal_sha256="ab" * 32,
        chain_id=31337,
        expires_at=NOW + timedelta(seconds=120),
    )
    assert verify(secret, token, NOW) == payload
    with pytest.raises(TokenError, match="bad_mac"):
        verify(b"x" * 32, token, NOW)
    head, body, mac = token.split(".")
    with pytest.raises(TokenError, match="bad_mac"):
        verify(secret, f"{head}.{body[:-2]}AA.{mac}", NOW)
    with pytest.raises(TokenError, match="expired"):
        verify(secret, token, NOW + timedelta(seconds=121))


# ---------------------------------------------------------------- resolver

BOOK = [
    BookEntry("abk_1", "Acme Corp", ACME, "user", True),
    BookEntry("abk_2", "Acme (new)", "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720", "agent", False),
]


def test_resolver_trusts_only_literals_and_verified_book() -> None:
    r = MandateResolver(registries(), BOOK, 31337)
    draft = MandateDraft(
        recipients=[
            DraftRecipient(label="Acme Corp"),
            DraftRecipient(label="Acme (new)"),
            DraftRecipient(label="Bob", address="0x90F79bf6EB2c4f870365E785982E1f101E93b906"),
            DraftRecipient(label="Eve", address=ACME),
        ],
        caps=[DraftCap(asset="tUSD", per_tx="150", session="300")],
        allowed_actions=["transfer"],
    )
    prompt = "Pay Acme Corp, and send Bob at 0x90f79bf6eb2c4f870365e785982e1f101e93b906 his share."
    m = r.resolve(draft, prompt, NOW)
    got = {(x.label, x.source) for x in m.recipients}
    assert got == {("Acme Corp", "book"), ("Bob", "literal")}
    assert any("Acme (new)" in u for u in m.unresolved)  # agent-written entry never trusted
    assert any("Eve" in u for u in m.unresolved)  # address not typed by the user
    assert m.per_tx_cap[TUSD] == 150_000_000 and m.session_cap[TUSD] == 300_000_000


def test_resolver_never_allows_delegation() -> None:
    r = MandateResolver(registries(), [], 31337)
    m = r.resolve(MandateDraft(allowed_actions=["delegate", "transfer"]), "x", NOW)
    assert ActionKind.DELEGATE not in m.allowed_actions
