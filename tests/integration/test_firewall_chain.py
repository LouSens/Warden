"""The full D5 firewall and the real signer against anvil: benign paths allowed and signed,
attack shapes blocked. This is M2's exit check on the chain."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
from eth_abi.abi import encode

from warden.chain.abi import checksum, load_artifact, selector_of
from warden.chain.history import HistoryIndex
from warden.chain.registry import Registries
from warden.chain.rpc import RpcClient
from warden.chain.world import World, units
from warden.clock import FixedClock
from warden.firewall.models import ActionKind, Proposal, ProposalKind, Verdict
from warden.firewall.pipeline import CONFIGS, Firewall
from warden.firewall.store import FirewallStore
from warden.mandate.schema import ApprovalCap, Mandate, RecipientRef, ServiceRef
from warden.policy.evaluator import load_policy
from warden.secrets import ANVIL_USER_KEY
from warden.signer.core import Signer
from warden.storage.database import Database
from warden.storage.migrate import migrate

pytestmark = pytest.mark.integration
SECRET = b"i" * 32
LOOKALIKE = checksum("0x3C44e0B1d7a5F4c2918b3E6f0D2a7C51b9e093BC")
TOKEN = load_artifact("AuthToken")


@dataclass
class Env:
    world: World
    rpc: RpcClient
    fw: Firewall
    signer: Signer
    session: str
    clock: FixedClock

    def tx(self, to: str, data: str = "0x", value: int = 0, **extra: object) -> Proposal:
        payload = {
            "chain_id": 31337,
            "from": self.world.user,
            "to": to,
            "value": str(value),
            "data": data,
            **extra,
        }
        return Proposal(kind=ProposalKind.TX, chain_id=31337, payload=payload)

    def transfer(self, symbol: str, to: str, whole: int) -> Proposal:
        t = self.world.token(symbol)
        return self.tx(t.address, TOKEN.encode_call("transfer", to, units(whole, t.decimals)))

    async def balance(self, symbol: str, who: str) -> int:
        t = self.world.token(symbol)
        out = await self.rpc.eth_call(t.address, TOKEN.encode_call("balanceOf", who))
        return int(TOKEN.decode_output("balanceOf", out)[0])


@pytest.fixture
async def env(world: World, rpc: RpcClient, tmp_path: Path) -> AsyncIterator[Env]:
    latest = await rpc.get_block("latest")
    clock = FixedClock.__new__(FixedClock)
    from datetime import UTC, datetime

    FixedClock.__init__(clock, datetime.fromtimestamp(int(latest["timestamp"], 16), UTC))
    db = await Database(tmp_path / "w.db").open()
    await migrate(db, "warden")
    sdb = await Database(tmp_path / "s.db").open()
    await migrate(sdb, "signer")
    store = FirewallStore(db)
    reg = Registries.from_world(world)
    await store.add_book_entry(
        "Acme Corp", world.accounts["acme"], 31337, "user", True, clock.now()
    )
    usd, tax, honey = world.token("tUSD"), world.token("tTAX"), world.token("tHONEY")
    mandate = Mandate(
        chain_ids=[31337],
        recipients=[RecipientRef(label="Acme Corp", address=world.accounts["acme"], source="book")],
        assets=[usd.address, tax.address, honey.address, world.token("tGOV").address],
        per_tx_cap={usd.address: units(200, 6)},
        session_cap={usd.address: units(1000, 6)},
        allowed_actions=[ActionKind.TRANSFER, ActionKind.APPROVE, ActionKind.SWAP, ActionKind.X402],
        spenders=[world.amm],
        approval_caps=[ApprovalCap(spender=world.amm, token=usd.address, cap=units(200, 6))],
        services=[
            ServiceRef(
                service="weather-api",
                pay_to=world.accounts["weather_api"],
                asset=usd.address,
                per_request_cap=units(1, 6),
            )
        ],
        expires_at=clock.now() + timedelta(hours=1),
    )
    mid = await store.insert_mandate(mandate, prompt_sha256="p", now=clock.now())
    sid = await store.create_session(mid, clock.now())
    from warden.simulate.simulator import ChainSimulator

    fw = Firewall(
        store=store,
        policy=load_policy(Path("policy.yaml").read_text()),
        registries=reg,
        clock=clock,
        token_secret=SECRET,
        simulator=ChainSimulator(rpc),
        history=HistoryIndex(rpc, world.user, reg),
        config=CONFIGS["D5"],
    )
    signer = Signer(
        key=ANVIL_USER_KEY,
        token_secret=SECRET,
        db=sdb,
        rpc=rpc,
        clock=clock,
        max_native_wei=10**18,
        max_token_amount=10**30,
    )
    yield Env(world, rpc, fw, signer, sid, clock)
    await db.close()
    await sdb.close()


async def test_invoice_payment_is_allowed_signed_and_lands(env: Env) -> None:
    acme = env.world.accounts["acme"]
    before = await env.balance("tUSD", acme)
    p = env.transfer("tUSD", acme, 120)
    started = time.perf_counter()
    d = await env.fw.evaluate(env.session, p)
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert d.verdict is Verdict.ALLOW, d.reasons
    assert d.effects is not None and d.effects.mode == "local"
    result = await env.signer.sign(d.decision_token or "", p)
    assert result.receipt_status == 1
    assert await env.balance("tUSD", acme) == before + units(120, 6)
    print(f"\nD5 decision latency (one sample, not a measurement): {elapsed_ms:.0f} ms")


async def test_lookalike_redirect_is_blocked(env: Env) -> None:
    d = await env.fw.evaluate(env.session, env.transfer("tUSD", LOOKALIKE, 120))
    codes = {f.code for f in d.findings}
    assert d.verdict is Verdict.BLOCK and d.decision_token is None
    assert {"lookalike_recipient", "recipient_not_in_mandate"} <= codes


async def test_address_poisoning_is_detected(env: Env) -> None:
    usd = env.world.token("tUSD")
    await env.rpc.send_and_wait(
        {
            "from": env.world.accounts["poisoner"],
            "to": usd.address,
            "data": TOKEN.encode_call("transferFrom", env.world.user, LOOKALIKE, 0),
        }
    )
    d = await env.fw.evaluate(env.session, env.transfer("tUSD", LOOKALIKE, 1))
    assert {"dust_origin", "lookalike_recipient"} <= {f.code for f in d.findings}


async def test_honeypot_and_tax_token_are_blocked(env: Env) -> None:
    usd = env.world.token("tUSD")
    amm = load_artifact("MiniAMM")
    # The user already approved the AMM earlier, so the swaps execute in simulation.
    await env.rpc.send_and_wait(
        {
            "from": env.world.user,
            "to": usd.address,
            "data": TOKEN.encode_call("approve", env.world.amm, units(1000, 6)),
        }
    )
    for symbol, code in (("tHONEY", "honeypot_sell_fails"), ("tTAX", "transfer_tax_over")):
        data = amm.encode_call(
            "swapExactIn",
            usd.address,
            env.world.token(symbol).address,
            units(50, 6),
            0,
            env.world.user,
        )
        d = await env.fw.evaluate(env.session, env.tx(env.world.amm, data))
        assert d.verdict is Verdict.BLOCK, (symbol, d.reasons)
        assert code in {f.code for f in d.findings}


async def test_hidden_drain_is_an_unexpected_outflow(env: Env) -> None:
    usd = env.world.token("tUSD")
    drainer = env.world.contracts["DrainerSpender"]
    await env.rpc.send_and_wait(
        {
            "from": env.world.user,
            "to": usd.address,
            "data": TOKEN.encode_call("approve", drainer, units(500, 6)),
        }
    )
    data = load_artifact("DrainerSpender").encode_call(
        "drain", usd.address, env.world.user, env.world.accounts["attacker"]
    )
    d = await env.fw.evaluate(env.session, env.tx(drainer, data))
    assert d.verdict is Verdict.BLOCK
    assert {"unknown_calldata", "unexpected_outflow"} <= {f.code for f in d.findings}


async def test_7702_delegation_is_blocked(env: Env) -> None:
    p = env.tx(
        env.world.accounts["acme"],
        authorization_list=[
            {"address": env.world.contracts["Sweeper7702"], "chain_id": 31337, "nonce": 0}
        ],
    )
    d = await env.fw.evaluate(env.session, p)
    assert d.verdict is Verdict.BLOCK and "no-delegation" in d.matched_rules
    assert d.effects is not None and d.effects.delegations


async def test_approve_then_swap_benign_path(env: Env) -> None:
    usd, gov = env.world.token("tUSD"), env.world.token("tGOV")
    approve = env.tx(usd.address, TOKEN.encode_call("approve", env.world.amm, units(100, 6)))
    d1 = await env.fw.evaluate(env.session, approve)
    assert d1.verdict is Verdict.ALLOW, d1.reasons
    assert (await env.signer.sign(d1.decision_token or "", approve)).receipt_status == 1
    data = load_artifact("MiniAMM").encode_call(
        "swapExactIn", usd.address, gov.address, units(100, 6), 1, env.world.user
    )
    swap = env.tx(env.world.amm, data)
    d2 = await env.fw.evaluate(env.session, swap)
    assert d2.verdict is Verdict.ALLOW, d2.reasons
    assert (await env.signer.sign(d2.decision_token or "", swap)).receipt_status == 1
    assert await env.balance("tGOV", env.world.user) > units(20, 18)


async def test_x402_payment_end_to_end(env: Env) -> None:
    usd = env.world.token("tUSD")
    weather = env.world.accounts["weather_api"]
    valid_before = int(env.clock.now().timestamp()) + 600
    nonce = "0x" + "ab" * 32
    p = Proposal(
        kind=ProposalKind.X402,
        chain_id=31337,
        payload={
            "from": env.world.user,
            "requirements": {
                "scheme": "exact",
                "asset": usd.address,
                "pay_to": weather,
                "amount": str(units("0.05", 6)),
                "nonce": nonce,
                "valid_before": valid_before,
                "service": "weather-api",
            },
        },
    )
    d = await env.fw.evaluate(env.session, p)
    assert d.verdict is Verdict.ALLOW, d.reasons
    signed = await env.signer.sign(d.decision_token or "", p)
    assert signed.signed is not None
    # The mock facilitator (relayer) settles the authorization on chain.
    call = (
        selector_of(
            "transferWithAuthorization(address,address,uint256,uint256,uint256,"
            "bytes32,uint8,bytes32,bytes32)"
        )
        + encode(
            [
                "address",
                "address",
                "uint256",
                "uint256",
                "uint256",
                "bytes32",
                "uint8",
                "bytes32",
                "bytes32",
            ],
            [
                env.world.user,
                weather,
                units("0.05", 6),
                0,
                valid_before,
                bytes.fromhex(nonce[2:]),
                signed.signed["v"],
                bytes.fromhex(signed.signed["r"][2:]),
                bytes.fromhex(signed.signed["s"][2:]),
            ],
        ).hex()
    )
    before = await env.balance("tUSD", weather)
    rcpt = await env.rpc.send_and_wait(
        {"from": env.world.accounts["relayer"], "to": usd.address, "data": call}
    )
    assert int(rcpt["status"], 16) == 1
    assert await env.balance("tUSD", weather) == before + units("0.05", 6)

    # Same nonce again: the firewall refuses before the chain would.
    again = await env.fw.evaluate(env.session, p)
    assert again.verdict is Verdict.BLOCK and "x402_nonce_reuse" in {f.code for f in again.findings}
    wrong = Proposal(
        kind=ProposalKind.X402,
        chain_id=31337,
        payload={
            **p.payload,
            "requirements": {
                **p.payload["requirements"],
                "nonce": "0x" + "cd" * 32,
                "pay_to": env.world.accounts["attacker"],
            },
        },
    )
    assert (await env.fw.evaluate(env.session, wrong)).verdict is Verdict.BLOCK
