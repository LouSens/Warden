"""The 25 checks (docs/policy.md §3). Each is a pure function of a CheckContext.

Checks are grouped by family (decoded, simulation, history) and registered by code; a defence
configuration enables families, not individual checks.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from typing import Any

from warden.checks.codes import CATALOGUE, Group
from warden.checks.context import CheckContext
from warden.firewall.models import UNLIMITED_THRESHOLD, ActionKind, Finding

CheckFn = Callable[[CheckContext], list[Finding]]
CHECKS: dict[str, CheckFn] = {}


def check(code: str) -> Callable[[CheckFn], CheckFn]:
    if code not in CATALOGUE:
        raise KeyError(f"unknown check code {code}")

    def register(fn: CheckFn) -> CheckFn:
        CHECKS[code] = fn
        return fn

    return register


def finding(code: str, **evidence: Any) -> Finding:
    return Finding(code=code, severity=CATALOGUE[code][1], evidence=evidence)


def run_checks(ctx: CheckContext, groups: set[Group]) -> list[Finding]:
    out: list[Finding] = []
    for code, fn in CHECKS.items():
        if CATALOGUE[code][0] in groups:
            out.extend(fn(ctx))
    return out


def _low(a: str | None) -> str:
    return (a or "").lower()


# ====================================================================== decoded-action checks


@check("chain_mismatch")
def chain_mismatch(ctx: CheckContext) -> list[Finding]:
    if ctx.proposal.chain_id not in ctx.mandate.chain_ids:
        return [
            finding("chain_mismatch", chain_id=ctx.proposal.chain_id, allowed=ctx.mandate.chain_ids)
        ]
    return []


@check("mandate_expired")
def mandate_expired(ctx: CheckContext) -> list[Finding]:
    if ctx.now >= ctx.mandate.expires_at:
        return [finding("mandate_expired", expires_at=ctx.mandate.expires_at.isoformat())]
    return []


@check("action_not_in_mandate")
def action_not_in_mandate(ctx: CheckContext) -> list[Finding]:
    allowed = set(ctx.mandate.allowed_actions)
    out = []
    for leaf in ctx.leaves:
        if leaf.kind in (ActionKind.UNKNOWN, ActionKind.DELEGATE):
            continue  # reported by unknown_calldata / delegation_present
        kind = leaf.kind
        if kind is ActionKind.PERMIT2:
            kind = ActionKind.PERMIT
        if kind not in allowed:
            out.append(
                finding(
                    "action_not_in_mandate",
                    action=leaf.kind.value,
                    allowed=sorted(a.value for a in allowed),
                )
            )
    return out


@check("recipient_not_in_mandate")
def recipient_not_in_mandate(ctx: CheckContext) -> list[Finding]:
    allowed = ctx.mandate.recipient_addresses()
    out = []
    for dest, leaf in ctx.value_destinations():
        if leaf.kind is ActionKind.X402:
            continue  # x402 payees are checked against the service registry
        if dest.lower() not in allowed and dest.lower() != ctx.sender.lower():
            out.append(
                finding(
                    "recipient_not_in_mandate",
                    destination=dest,
                    mandate_recipients=[r.label for r in ctx.mandate.recipients],
                )
            )
    for leaf in ctx.leaves:
        if leaf.kind is ActionKind.SWAP and leaf.to and leaf.to.lower() != ctx.sender.lower():
            out.append(
                finding(
                    "recipient_not_in_mandate",
                    destination=leaf.to,
                    note="swap output sent to another address",
                )
            )
    return out


@check("unverified_book_entry")
def unverified_book_entry(ctx: CheckContext) -> list[Finding]:
    allowed = ctx.mandate.recipient_addresses()
    out = []
    for dest, _ in ctx.value_destinations():
        if dest.lower() in allowed:
            continue
        for e in ctx.book:
            if e.address.lower() == dest.lower() and not e.trusted:
                out.append(
                    finding(
                        "unverified_book_entry",
                        destination=dest,
                        label=e.label,
                        provenance=e.provenance,
                        verified=e.verified,
                    )
                )
    return out


def _cap_findings(ctx: CheckContext, which: str) -> list[Finding]:
    out = []
    for asset, amount in ctx.outflows().items():
        if amount <= 0:
            continue
        asset_key = "native" if asset == "native" else asset
        if which == "per_tx":
            cap = ctx.mandate.cap_for(asset_key, "per_tx")
            if amount > cap:
                out.append(
                    finding(
                        "per_tx_cap",
                        asset=ctx.registries.symbol(asset_key),
                        outflow=str(amount),
                        cap=str(cap),
                    )
                )
        else:
            cap = ctx.mandate.cap_for(asset_key, "session")
            spent = ctx.spent.get(asset, 0)
            if spent + amount > cap:
                out.append(
                    finding(
                        "session_cap",
                        asset=ctx.registries.symbol(asset_key),
                        spent=str(spent),
                        outflow=str(amount),
                        cap=str(cap),
                    )
                )
    return out


@check("per_tx_cap")
def per_tx_cap(ctx: CheckContext) -> list[Finding]:
    return _cap_findings(ctx, "per_tx")


@check("session_cap")
def session_cap(ctx: CheckContext) -> list[Finding]:
    return _cap_findings(ctx, "session")


_APPROVALS = (ActionKind.APPROVE, ActionKind.PERMIT, ActionKind.PERMIT2)


@check("unlimited_approval")
def unlimited_approval(ctx: CheckContext) -> list[Finding]:
    out = []
    for leaf in ctx.leaves:
        if leaf.kind in _APPROVALS and (leaf.amount or 0) >= UNLIMITED_THRESHOLD:
            out.append(
                finding(
                    "unlimited_approval",
                    spender=leaf.spender,
                    token=leaf.token,
                    kind=leaf.kind.value,
                )
            )
        if leaf.kind is ActionKind.SET_APPROVAL_FOR_ALL and leaf.approved:
            out.append(
                finding(
                    "unlimited_approval",
                    spender=leaf.spender,
                    token=leaf.token,
                    kind=leaf.kind.value,
                )
            )
    return out


@check("unknown_spender")
def unknown_spender(ctx: CheckContext) -> list[Finding]:
    spenders = ctx.mandate.spender_addresses()
    out = []
    for leaf in ctx.leaves:
        if leaf.kind in (ActionKind.APPROVE, ActionKind.SET_APPROVAL_FOR_ALL):
            revoking = (leaf.kind is ActionKind.APPROVE and leaf.amount == 0) or (
                leaf.kind is ActionKind.SET_APPROVAL_FOR_ALL and not leaf.approved
            )
            if not revoking and _low(leaf.spender) not in spenders:
                out.append(finding("unknown_spender", spender=leaf.spender, token=leaf.token))
    return out


@check("approval_over_cap")
def approval_over_cap(ctx: CheckContext) -> list[Finding]:
    out = []
    for leaf in ctx.leaves:
        if leaf.kind is ActionKind.APPROVE and leaf.spender and leaf.token:
            cap = ctx.mandate.approval_cap(leaf.spender, leaf.token)
            if (leaf.amount or 0) > cap:
                out.append(
                    finding(
                        "approval_over_cap",
                        spender=leaf.spender,
                        token=ctx.registries.symbol(leaf.token),
                        amount=str(leaf.amount),
                        cap=str(cap),
                    )
                )
    return out


@check("permit_spender_unknown")
def permit_spender_unknown(ctx: CheckContext) -> list[Finding]:
    spenders = ctx.mandate.spender_addresses()
    return [
        finding(
            "permit_spender_unknown", spender=leaf.spender, token=leaf.token, kind=leaf.kind.value
        )
        for leaf in ctx.leaves
        if leaf.kind in (ActionKind.PERMIT, ActionKind.PERMIT2)
        and _low(leaf.spender) not in spenders
    ]


@check("permit_deadline_too_long")
def permit_deadline_too_long(ctx: CheckContext) -> list[Finding]:
    limit = int((ctx.now + timedelta(seconds=ctx.params.permit_max_deadline_s)).timestamp())
    return [
        finding("permit_deadline_too_long", deadline=leaf.deadline, max_deadline=limit)
        for leaf in ctx.leaves
        if leaf.kind in (ActionKind.PERMIT, ActionKind.PERMIT2) and (leaf.deadline or 0) > limit
    ]


@check("delegation_present")
def delegation_present(ctx: CheckContext) -> list[Finding]:
    delegates = {leaf.delegate for leaf in ctx.leaves if leaf.kind is ActionKind.DELEGATE}
    if ctx.effects is not None:
        delegates |= {d.delegate for d in ctx.effects.delegations}
    return [finding("delegation_present", delegate=d) for d in sorted(x for x in delegates if x)]


@check("token_not_in_registry")
def token_not_in_registry(ctx: CheckContext) -> list[Finding]:
    return [
        finding("token_not_in_registry", token=t, symbol=ctx.registries.symbol(t))
        for t in sorted(ctx.tokens_touched())
        if not ctx.registries.is_registered(t)
    ]


def _x402_leaves(ctx: CheckContext) -> list[Any]:
    return [leaf for leaf in ctx.leaves if leaf.kind is ActionKind.X402]


@check("x402_price_over")
def x402_price_over(ctx: CheckContext) -> list[Finding]:
    out = []
    for leaf in _x402_leaves(ctx):
        svc = ctx.mandate.service_by_name(leaf.service)
        if svc is not None and (leaf.amount or 0) > svc.per_request_cap:
            out.append(
                finding(
                    "x402_price_over",
                    service=leaf.service,
                    price=str(leaf.amount),
                    cap=str(svc.per_request_cap),
                )
            )
    return out


@check("x402_payto_mismatch")
def x402_payto_mismatch(ctx: CheckContext) -> list[Finding]:
    out = []
    for leaf in _x402_leaves(ctx):
        svc = ctx.mandate.service_by_name(leaf.service)
        if svc is None:
            out.append(
                finding(
                    "x402_payto_mismatch",
                    service=leaf.service,
                    pay_to=leaf.to,
                    note="service not in the mandate",
                )
            )
        elif _low(leaf.to) != svc.pay_to.lower() or _low(leaf.token) != svc.asset.lower():
            out.append(
                finding(
                    "x402_payto_mismatch",
                    service=leaf.service,
                    pay_to=leaf.to,
                    registered=svc.pay_to,
                )
            )
    return out


@check("x402_nonce_reuse")
def x402_nonce_reuse(ctx: CheckContext) -> list[Finding]:
    return [
        finding("x402_nonce_reuse", nonce=leaf.nonce)
        for leaf in _x402_leaves(ctx)
        if leaf.nonce and leaf.nonce.lower() in ctx.used_x402_nonces
    ]


@check("unknown_calldata")
def unknown_calldata(ctx: CheckContext) -> list[Finding]:
    return [
        finding("unknown_calldata", target=leaf.target, selector=leaf.selector, note=leaf.note)
        for leaf in ctx.leaves
        if leaf.kind is ActionKind.UNKNOWN
    ]


# ====================================================================== simulation checks


@check("unexpected_outflow")
def unexpected_outflow(ctx: CheckContext) -> list[Finding]:
    if not ctx.simulated:
        return []
    declared = ctx.declared_outflows()
    out = []
    for asset, amount in ctx.outflows().items():
        extra = amount - declared.get(asset, 0)
        if extra > 0:
            out.append(
                finding(
                    "unexpected_outflow",
                    asset=ctx.registries.symbol(asset),
                    simulated=str(amount),
                    declared=str(declared.get(asset, 0)),
                )
            )
    return out


@check("honeypot_sell_fails")
def honeypot_sell_fails(ctx: CheckContext) -> list[Finding]:
    if ctx.simulated and ctx.effects is not None and ctx.effects.honeypot_sell_reverted:
        tokens = [leaf.token_out for leaf in ctx.leaves if leaf.kind is ActionKind.SWAP]
        return [finding("honeypot_sell_fails", tokens=tokens)]
    return []


@check("transfer_tax_over")
def transfer_tax_over(ctx: CheckContext) -> list[Finding]:
    if not ctx.simulated or ctx.effects is None or ctx.effects.transfer_tax_bps is None:
        return []
    if ctx.effects.transfer_tax_bps > ctx.params.transfer_tax_max_bps:
        return [
            finding(
                "transfer_tax_over",
                tax_bps=ctx.effects.transfer_tax_bps,
                max_bps=ctx.params.transfer_tax_max_bps,
            )
        ]
    return []


@check("simulation_reverted")
def simulation_reverted(ctx: CheckContext) -> list[Finding]:
    if ctx.simulated and ctx.effects is not None and ctx.effects.reverted:
        return [finding("simulation_reverted", reason=ctx.effects.revert_reason)]
    return []


# ====================================================================== history checks


def match_lengths(a: str, b: str) -> tuple[int, int]:
    x, y = a.lower().removeprefix("0x"), b.lower().removeprefix("0x")
    prefix = 0
    while prefix < len(x) and x[prefix] == y[prefix]:
        prefix += 1
    suffix = 0
    while suffix < len(x) and x[-1 - suffix] == y[-1 - suffix]:
        suffix += 1
    return prefix, suffix


def _history_targets(ctx: CheckContext) -> list[str]:
    targets = [d for d, _ in ctx.value_destinations()]
    targets += [
        leaf.spender
        for leaf in ctx.leaves
        if leaf.kind in (*_APPROVALS, ActionKind.SET_APPROVAL_FOR_ALL) and leaf.spender
    ]
    return [t for t in targets if t.lower() != ctx.sender.lower()]


@check("lookalike_recipient")
def lookalike_recipient(ctx: CheckContext) -> list[Finding]:
    known = ctx.known_counterparties()
    out = []
    for dest in _history_targets(ctx):
        if dest.lower() in known:
            continue
        for addr, label in known.items():
            p, s = match_lengths(dest, addr)
            if p >= ctx.params.lookalike_prefix and s >= ctx.params.lookalike_suffix:
                out.append(
                    finding(
                        "lookalike_recipient",
                        destination=dest,
                        imitates=addr,
                        imitates_label=label,
                        prefix_match=p,
                        suffix_match=s,
                    )
                )
                break
    return out


@check("dust_origin")
def dust_origin(ctx: CheckContext) -> list[Finding]:
    if ctx.history is None:
        return []
    threshold = float(ctx.params.dust_threshold_usd_equiv)
    out = []
    for dest in _history_targets(ctx):
        d = dest.lower()
        if d in ctx.history.own_destinations or d not in ctx.history.log_only:
            continue
        seen = ctx.history.log_only[d]
        if seen is None or seen <= threshold:
            out.append(finding("dust_origin", destination=dest, largest_seen_usd=seen))
    return out


@check("first_seen_recipient")
def first_seen_recipient(ctx: CheckContext) -> list[Finding]:
    if ctx.history is None:
        return []
    exempt = {s.pay_to.lower() for s in ctx.registries.services.values()}
    return [
        finding("first_seen_recipient", destination=dest)
        for dest, _ in ctx.value_destinations()
        if dest.lower() not in ctx.history.own_destinations
        and dest.lower() not in exempt
        and dest.lower() != ctx.sender.lower()
    ]


def outflow_usd(ctx: CheckContext) -> Decimal | None:
    total = Decimal(0)
    for asset, amount in ctx.outflows().items():
        value = ctx.registries.usd_value("native" if asset == "native" else asset, amount)
        if value is None:
            return None
        total += value
    return total


assert set(CHECKS) == set(CATALOGUE), f"missing checks: {set(CATALOGUE) - set(CHECKS)}"
