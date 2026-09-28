"""Every check has one positive and one negative fixture (CLAUDE.md §5)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest
from _fw import (
    ACME,
    AMM,
    ATTACKER,
    BOB,
    LOOKALIKE,
    MAX,
    NOW,
    SWEEPER,
    TDAI,
    TGOV,
    THONEY,
    TUSD,
    USER,
    WEATHER,
    approve,
    ctx,
    mandate,
    permit_typed,
    swap,
    transfer,
    tx,
    x402,
)

from warden.checks.catalogue import CHECKS, match_lengths
from warden.checks.codes import CATALOGUE
from warden.checks.context import BookEntry, CheckContext, HistoryView
from warden.firewall.models import ActionKind, AssetDelta, Effects
from warden.mandate.schema import ServiceRef

HIST = HistoryView(
    own_destinations=frozenset({ACME.lower(), BOB.lower()}), log_only={LOOKALIKE.lower(): 0.0}
)
SWAP_MANDATE = mandate(
    allowed_actions=[ActionKind.SWAP],
    spenders=[AMM],
    per_tx_cap={TUSD: 500_000_000},
    session_cap={TUSD: 500_000_000},
)
X402_MANDATE = mandate(
    allowed_actions=[ActionKind.X402],
    recipients=[],
    services=[
        ServiceRef(service="weather-api", pay_to=WEATHER, asset=TUSD, per_request_cap=100_000)
    ],
)


def sim(*deltas: tuple[str, str, int], **kw: object) -> Effects:
    return Effects(
        mode="local", assets=[AssetDelta(address=a, token=t, delta=d) for a, t, d in deltas], **kw
    )  # type: ignore[arg-type]


PAY_ACME = transfer(TUSD, ACME, 120_000_000)

CASES: dict[str, tuple[Callable[[], CheckContext], Callable[[], CheckContext]]] = {
    "chain_mismatch": (lambda: ctx(PAY_ACME, m=mandate(chain_ids=[84532])), lambda: ctx(PAY_ACME)),
    "mandate_expired": (
        lambda: ctx(PAY_ACME, m=mandate(expires_at=NOW - timedelta(seconds=1))),
        lambda: ctx(PAY_ACME),
    ),
    "action_not_in_mandate": (lambda: ctx(approve(TUSD, AMM, 1)), lambda: ctx(PAY_ACME)),
    "recipient_not_in_mandate": (lambda: ctx(transfer(TUSD, ATTACKER, 1)), lambda: ctx(PAY_ACME)),
    "unverified_book_entry": (
        lambda: ctx(
            transfer(TUSD, ATTACKER, 1),
            book=[BookEntry("abk_1", "Acme (new)", ATTACKER, "agent", False)],
        ),
        lambda: ctx(transfer(TUSD, ATTACKER, 1)),
    ),
    "per_tx_cap": (lambda: ctx(transfer(TUSD, ACME, 150_000_001)), lambda: ctx(PAY_ACME)),
    "session_cap": (
        lambda: ctx(PAY_ACME, spent={TUSD.lower(): 200_000_000}),
        lambda: ctx(PAY_ACME, spent={TUSD.lower(): 100_000_000}),
    ),
    "unlimited_approval": (
        lambda: ctx(approve(TUSD, AMM, MAX)),
        lambda: ctx(approve(TUSD, AMM, 10)),
    ),
    "unknown_spender": (
        lambda: ctx(approve(TUSD, ATTACKER, 10)),
        lambda: ctx(approve(TUSD, AMM, 10), m=SWAP_MANDATE),
    ),
    "approval_over_cap": (
        lambda: ctx(approve(TUSD, AMM, 600_000_000), m=SWAP_MANDATE),
        lambda: ctx(approve(TUSD, AMM, 100_000_000), m=SWAP_MANDATE),
    ),
    "permit_spender_unknown": (
        lambda: ctx(permit_typed(ATTACKER, 1, int(NOW.timestamp()) + 60)),
        lambda: ctx(permit_typed(AMM, 1, int(NOW.timestamp()) + 60), m=SWAP_MANDATE),
    ),
    "permit_deadline_too_long": (
        lambda: ctx(permit_typed(AMM, 1, int(NOW.timestamp()) + 10 * 86400)),
        lambda: ctx(permit_typed(AMM, 1, int(NOW.timestamp()) + 60)),
    ),
    "delegation_present": (
        lambda: ctx(
            tx(ACME, authorization_list=[{"address": SWEEPER, "chain_id": 31337, "nonce": 0}])
        ),
        lambda: ctx(PAY_ACME),
    ),
    "token_not_in_registry": (
        lambda: ctx(swap(TUSD, THONEY, 1), m=SWAP_MANDATE),
        lambda: ctx(swap(TUSD, TGOV, 1), m=SWAP_MANDATE),
    ),
    "x402_price_over": (
        lambda: ctx(x402(amount=100_001), m=X402_MANDATE),
        lambda: ctx(x402(amount=100_000), m=X402_MANDATE),
    ),
    "x402_payto_mismatch": (
        lambda: ctx(x402(pay_to=ATTACKER), m=X402_MANDATE),
        lambda: ctx(x402(), m=X402_MANDATE),
    ),
    "x402_nonce_reuse": (
        lambda: ctx(x402(), m=X402_MANDATE, used_nonces=frozenset({"0x" + "11" * 32})),
        lambda: ctx(x402(), m=X402_MANDATE),
    ),
    "unknown_calldata": (lambda: ctx(tx(TUSD, "0xdeadbeef")), lambda: ctx(PAY_ACME)),
    "unexpected_outflow": (
        lambda: ctx(
            PAY_ACME,
            effects=sim(
                (USER, TUSD, -130_000_000), (ACME, TUSD, 120_000_000), (ATTACKER, TUSD, 10_000_000)
            ),
        ),
        lambda: ctx(PAY_ACME, effects=sim((USER, TUSD, -120_000_000), (ACME, TUSD, 120_000_000))),
    ),
    "honeypot_sell_fails": (
        lambda: ctx(
            swap(TUSD, THONEY, 1),
            m=SWAP_MANDATE,
            effects=sim((USER, TUSD, -1), honeypot_sell_reverted=True),
        ),
        lambda: ctx(
            swap(TUSD, TGOV, 1),
            m=SWAP_MANDATE,
            effects=sim((USER, TUSD, -1), honeypot_sell_reverted=False),
        ),
    ),
    "transfer_tax_over": (
        lambda: ctx(
            swap(TUSD, TGOV, 1),
            m=SWAP_MANDATE,
            effects=sim((USER, TUSD, -1), transfer_tax_bps=1000),
        ),
        lambda: ctx(
            swap(TUSD, TGOV, 1), m=SWAP_MANDATE, effects=sim((USER, TUSD, -1), transfer_tax_bps=0)
        ),
    ),
    "simulation_reverted": (
        lambda: ctx(PAY_ACME, effects=Effects(mode="local", reverted=True)),
        lambda: ctx(PAY_ACME, effects=Effects(mode="local")),
    ),
    "lookalike_recipient": (
        lambda: ctx(transfer(TUSD, LOOKALIKE, 1), history=HIST),
        lambda: ctx(transfer(TUSD, ATTACKER, 1), history=HIST),
    ),
    "dust_origin": (
        lambda: ctx(transfer(TUSD, LOOKALIKE, 1), history=HIST),
        lambda: ctx(transfer(TUSD, BOB, 1), history=HIST),
    ),
    "first_seen_recipient": (
        lambda: ctx(transfer(TUSD, ATTACKER, 1), history=HIST),
        lambda: ctx(PAY_ACME, history=HIST),
    ),
}


def test_every_check_has_cases() -> None:
    assert set(CASES) == set(CATALOGUE) == set(CHECKS)
    assert len(CATALOGUE) == 25


@pytest.mark.parametrize("code", sorted(CASES))
def test_positive(code: str) -> None:
    findings = CHECKS[code](CASES[code][0]())
    assert findings, f"{code} should fire"
    assert all(f.code == code for f in findings)


@pytest.mark.parametrize("code", sorted(CASES))
def test_negative(code: str) -> None:
    assert CHECKS[code](CASES[code][1]()) == [], f"{code} should not fire"


def test_lookalike_counts_prefix_and_suffix() -> None:
    assert match_lengths(LOOKALIKE, ACME) == (4, 4)
    assert match_lengths(ACME, ACME) == (40, 40)


def test_known_counterparties_exclude_log_only_addresses() -> None:
    c = ctx(transfer(TUSD, LOOKALIKE, 1), history=HIST)
    assert LOOKALIKE.lower() not in c.known_counterparties()
    assert ACME.lower() in c.known_counterparties()


def test_declared_outflows() -> None:
    assert ctx(PAY_ACME).declared_outflows() == {TUSD.lower(): 120_000_000}
    assert ctx(swap(TUSD, TGOV, 5), m=SWAP_MANDATE).declared_outflows() == {TUSD.lower(): 5}
    assert ctx(tx(ACME, value=7)).declared_outflows() == {"native": 7}
    assert ctx(approve(TDAI, AMM, 9)).declared_outflows() == {}
