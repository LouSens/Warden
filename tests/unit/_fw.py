"""Chain-free fixtures for firewall unit tests: a small registry, a mandate, and proposal builders."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from eth_abi.abi import encode

from warden.chain.abi import checksum, selector_of
from warden.chain.registry import RegisteredService, RegisteredToken, Registries
from warden.checks.context import BookEntry, CheckContext, HistoryView
from warden.decode.decoder import CallDecoder
from warden.firewall.models import ActionKind, Effects, Proposal, ProposalKind
from warden.mandate.schema import Mandate, RecipientRef
from warden.policy.schema import Params

NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)

USER = checksum("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
ACME = checksum("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
BOB = checksum("0x90F79bf6EB2c4f870365E785982E1f101E93b906")
LOOKALIKE = checksum("0x3C44e0B1d7a5F4c2918b3E6f0D2a7C51b9e093BC")
ATTACKER = checksum("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")
WEATHER = checksum("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc")

TUSD = checksum("0x5FbDB2315678afecb367f032d93F642f64180aa3")
TDAI = checksum("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512")
TGOV = checksum("0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0")
THONEY = checksum("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
AMM = checksum("0x5FC8d32690cc91D4c39d9d3abcBD16989F875707")
SWEEPER = checksum("0xA15BB66138824a1c7167f5E85b957d04Dd34E468")

MAX = 2**256 - 1


def registries() -> Registries:
    reg = Registries()
    for sym, addr, dec, price in (
        ("tUSD", TUSD, 6, "1"),
        ("tDAI", TDAI, 18, "1"),
        ("tGOV", TGOV, 18, "10"),
    ):
        reg.tokens[addr.lower()] = RegisteredToken(sym, addr, dec, Decimal(price))
        reg.all_token_meta[addr.lower()] = (sym, dec)
    reg.all_token_meta[THONEY.lower()] = ("tHONEY", 18)
    reg.spenders[AMM.lower()] = "MiniAMM"
    reg.services["weather-api"] = RegisteredService("weather-api", WEATHER, TUSD)
    return reg


def mandate(**overrides: Any) -> Mandate:
    base: dict[str, Any] = {
        "chain_ids": [31337],
        "recipients": [RecipientRef(label="Acme Corp", address=ACME, source="book")],
        "assets": [TUSD],
        "per_tx_cap": {TUSD: 150_000_000},
        "session_cap": {TUSD: 300_000_000},
        "allowed_actions": [ActionKind.TRANSFER],
        "expires_at": NOW + timedelta(hours=1),
    }
    base.update(overrides)
    return Mandate(**base)


def calldata(signature: str, types: list[str], args: list[Any]) -> str:
    return selector_of(signature) + encode(types, args).hex()


def tx(to: str, data: str = "0x", value: int = 0, **extra: Any) -> Proposal:
    payload = {"chain_id": 31337, "from": USER, "to": to, "value": str(value), "data": data}
    payload.update(extra)
    return Proposal(kind=ProposalKind.TX, chain_id=int(payload["chain_id"]), payload=payload)


def transfer(token: str, to: str, amount: int) -> Proposal:
    return tx(token, calldata("transfer(address,uint256)", ["address", "uint256"], [to, amount]))


def approve(token: str, spender: str, amount: int) -> Proposal:
    return tx(
        token, calldata("approve(address,uint256)", ["address", "uint256"], [spender, amount])
    )


def swap(t_in: str, t_out: str, amount: int, to: str = USER) -> Proposal:
    return tx(
        AMM,
        calldata(
            "swapExactIn(address,address,uint256,uint256,address)",
            ["address", "address", "uint256", "uint256", "address"],
            [t_in, t_out, amount, 0, to],
        ),
    )


def permit_typed(spender: str, value: int, deadline: int) -> Proposal:
    td = {
        "types": {"EIP712Domain": [], "Permit": []},
        "primaryType": "Permit",
        "domain": {"name": "Test DAI", "version": "1", "chainId": 31337, "verifyingContract": TDAI},
        "message": {
            "owner": USER,
            "spender": spender,
            "value": value,
            "nonce": 0,
            "deadline": deadline,
        },
    }
    return Proposal(
        kind=ProposalKind.TYPED_DATA, chain_id=31337, payload={"from": USER, "typed_data": td}
    )


def x402(
    pay_to: str = WEATHER,
    amount: int = 50_000,
    nonce: str = "0x" + "11" * 32,
    service: str = "weather-api",
) -> Proposal:
    return Proposal(
        kind=ProposalKind.X402,
        chain_id=31337,
        payload={
            "from": USER,
            "requirements": {
                "scheme": "exact",
                "asset": TUSD,
                "pay_to": pay_to,
                "amount": str(amount),
                "nonce": nonce,
                "valid_before": int(NOW.timestamp()) + 600,
                "service": service,
            },
        },
    )


def ctx(
    proposal: Proposal,
    *,
    m: Mandate | None = None,
    effects: Effects | None = None,
    history: HistoryView | None = None,
    book: list[BookEntry] | None = None,
    spent: dict[str, int] | None = None,
    used_nonces: frozenset[str] = frozenset(),
    params: Params | None = None,
) -> CheckContext:
    return CheckContext(
        proposal=proposal,
        action=CallDecoder().decode(proposal),
        mandate=m or mandate(),
        registries=registries(),
        params=params or Params(),
        now=NOW,
        sender=USER,
        effects=effects,
        spent=spent or {},
        book=book or [],
        history=history,
        used_x402_nonces=used_nonces,
    )
