"""Human-readable reasons for a decision, built from findings and the action (never by an LLM)."""

from __future__ import annotations

from typing import Any

from warden.chain.registry import Registries
from warden.firewall.models import Action, ActionKind, Finding, Verdict


def short(addr: str | None) -> str:
    if not addr:
        return "?"
    return f"{addr[:6]}…{addr[-4:]}"


def _amount(reg: Registries, asset_symbol: str, raw: Any) -> str:
    return f"{raw} (base units) {asset_symbol}"


def finding_text(f: Finding, reg: Registries) -> str:
    e = f.evidence
    match f.code:
        case "lookalike_recipient":
            return (
                f"Recipient {short(e.get('destination'))} imitates {e.get('imitates_label')} "
                f"(first {e.get('prefix_match')} and last {e.get('suffix_match')} characters "
                "match) but is a different address."
            )
        case "recipient_not_in_mandate":
            return f"Recipient {short(e.get('destination'))} is not in the mandate."
        case "per_tx_cap":
            return f"Outflow of {e.get('asset')} exceeds the per-transaction cap."
        case "session_cap":
            return f"This would take the session over its {e.get('asset')} cap."
        case "unlimited_approval":
            return f"Unlimited approval to {short(e.get('spender'))}."
        case "unknown_spender" | "permit_spender_unknown":
            return f"Spender {short(e.get('spender'))} is not allowed by the mandate."
        case "approval_over_cap":
            return f"Approval of {e.get('token')} is above the mandate's cap."
        case "delegation_present":
            return f"EIP-7702 delegation to {short(e.get('delegate'))}: always blocked."
        case "honeypot_sell_fails":
            return "The token cannot be sold back after buying (honeypot)."
        case "transfer_tax_over":
            return f"The token takes a {int(e.get('tax_bps', 0)) / 100:.1f}% transfer tax."
        case "token_not_in_registry":
            return f"Token {e.get('symbol')} is not in the token registry."
        case "unexpected_outflow":
            return f"Simulation shows more {e.get('asset')} leaving than the action declares."
        case "chain_mismatch":
            return f"Chain {e.get('chain_id')} is not allowed by the mandate."
        case "mandate_expired":
            return "The mandate has expired."
        case "action_not_in_mandate":
            return f"A {e.get('action')} action is not allowed by the mandate."
        case "unverified_book_entry":
            return f"Recipient comes from an unverified ({e.get('provenance')}) address-book entry."
        case "x402_price_over":
            return f"x402 price for {e.get('service')} is above the mandate's cap."
        case "x402_payto_mismatch":
            return f"x402 payee {short(e.get('pay_to'))} is not the registered payee."
        case "x402_nonce_reuse":
            return "This x402 payment authorization was already used."
        case "unknown_calldata":
            return "Warden cannot decode this call."
        case "dust_origin":
            return (
                f"Recipient {short(e.get('destination'))} appears in your history only "
                "through zero-value or dust transfers."
            )
        case "first_seen_recipient":
            return f"You have never paid {short(e.get('destination'))} before."
        case "permit_deadline_too_long":
            return "The signature stays valid for longer than the policy allows."
        case "simulation_reverted":
            return "The transaction reverts in simulation."
    return f.code


def action_text(action: Action, reg: Registries) -> str:
    leaves = action.leaves()
    parts = []
    for leaf in leaves:
        if leaf.kind in (ActionKind.TRANSFER, ActionKind.X402) and leaf.token:
            parts.append(
                f"{leaf.kind.value} {reg.human(leaf.token, leaf.amount or 0)} to {short(leaf.to)}"
            )
        elif leaf.kind is ActionKind.SWAP and leaf.token_in and leaf.token_out:
            parts.append(
                f"swap {reg.human(leaf.token_in, leaf.amount_in or 0)} for "
                f"{reg.symbol(leaf.token_out)}"
            )
        elif leaf.kind in (ActionKind.APPROVE, ActionKind.PERMIT, ActionKind.PERMIT2):
            parts.append(
                f"{leaf.kind.value} {short(leaf.spender)} on {reg.symbol(leaf.token or '')}"
            )
        else:
            parts.append(leaf.kind.value)
    return "; ".join(parts)


def reasons_for(
    verdict: Verdict,
    findings: list[Finding],
    action: Action,
    reg: Registries,
    deciding_rules: list[str],
) -> list[str]:
    ranked = sorted(findings, key=lambda f: -f.severity.rank)
    lines = [finding_text(f, reg) for f in ranked]
    if verdict is Verdict.ALLOW:
        lines.insert(0, f"Within the mandate: {action_text(action, reg)}.")
    elif not lines:
        lines.append("No rule allowed this action (default deny).")
    if deciding_rules:
        lines.append(f"Rule: {', '.join(deciding_rules)}.")
    # de-duplicate, keep order
    return list(dict.fromkeys(lines))
