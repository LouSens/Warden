"""The canonical list of check codes (docs/policy.md §3). Nothing else may invent a code."""

from __future__ import annotations

from typing import Final, Literal

from warden.firewall.models import Severity

Group = Literal["decoded", "simulation", "history"]

CATALOGUE: Final[dict[str, tuple[Group, Severity]]] = {
    "chain_mismatch": ("decoded", Severity.CRITICAL),
    "mandate_expired": ("decoded", Severity.HIGH),
    "action_not_in_mandate": ("decoded", Severity.HIGH),
    "recipient_not_in_mandate": ("decoded", Severity.HIGH),
    "unverified_book_entry": ("decoded", Severity.MEDIUM),
    "per_tx_cap": ("decoded", Severity.HIGH),
    "session_cap": ("decoded", Severity.HIGH),
    "unlimited_approval": ("decoded", Severity.CRITICAL),
    "unknown_spender": ("decoded", Severity.HIGH),
    "approval_over_cap": ("decoded", Severity.HIGH),
    "permit_spender_unknown": ("decoded", Severity.HIGH),
    "permit_deadline_too_long": ("decoded", Severity.MEDIUM),
    "delegation_present": ("decoded", Severity.CRITICAL),
    "token_not_in_registry": ("decoded", Severity.MEDIUM),
    "x402_price_over": ("decoded", Severity.MEDIUM),
    "x402_payto_mismatch": ("decoded", Severity.CRITICAL),
    "x402_nonce_reuse": ("decoded", Severity.CRITICAL),
    "unknown_calldata": ("decoded", Severity.MEDIUM),
    "unexpected_outflow": ("simulation", Severity.HIGH),
    "honeypot_sell_fails": ("simulation", Severity.CRITICAL),
    "transfer_tax_over": ("simulation", Severity.HIGH),
    "simulation_reverted": ("simulation", Severity.LOW),
    "lookalike_recipient": ("history", Severity.CRITICAL),
    "dust_origin": ("history", Severity.HIGH),
    "first_seen_recipient": ("history", Severity.LOW),
}

CHECK_CODES: Final[frozenset[str]] = frozenset(CATALOGUE)

# Findings that mean "this action is outside the mandate". Mandate satisfaction (the intent rule)
# is exactly the absence of all of them.
MANDATE_VIOLATIONS: Final[frozenset[str]] = frozenset(
    {
        "chain_mismatch",
        "mandate_expired",
        "action_not_in_mandate",
        "recipient_not_in_mandate",
        "per_tx_cap",
        "session_cap",
        "unlimited_approval",
        "unknown_spender",
        "approval_over_cap",
        "permit_spender_unknown",
        "delegation_present",
        "x402_price_over",
        "x402_payto_mismatch",
        "x402_nonce_reuse",
        "unknown_calldata",
        "unexpected_outflow",
    }
)
