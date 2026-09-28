"""Turn a mandate *draft* (from the extractor model, or typed by hand) into a Mandate.

This is code, not a model, and it is where invariant 2 is enforced for recipients:

* an address is accepted only if it appears literally in the trusted prompt (``literal``), or
* a label is accepted only if it matches a *trusted* address-book entry (``book``: provenance user
  or import, verified).

Agent-written entries and anything else go to ``unresolved``; an action touching them can never be
allowed.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation

from pydantic import BaseModel, Field

from warden.chain.abi import checksum
from warden.chain.registry import Registries
from warden.checks.context import BookEntry
from warden.firewall.models import NATIVE, ActionKind
from warden.mandate.schema import ApprovalCap, Mandate, RecipientRef, ServiceRef

MAX_TTL_S = 24 * 3600


class DraftRecipient(BaseModel):
    label: str
    address: str | None = None


class DraftCap(BaseModel):
    asset: str
    per_tx: str | None = None
    session: str | None = None


class DraftService(BaseModel):
    service: str
    per_request_cap: str


class DraftApproval(BaseModel):
    spender: str
    asset: str
    cap: str


class MandateDraft(BaseModel):
    recipients: list[DraftRecipient] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    caps: list[DraftCap] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    spenders: list[str] = Field(default_factory=list)
    approvals: list[DraftApproval] = Field(default_factory=list)
    services: list[DraftService] = Field(default_factory=list)
    max_slippage_bps: int | None = None
    expires_in_s: int | None = None
    constraints: list[str] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)


def _units(text: str, decimals: int) -> int | None:
    try:
        value = Decimal(text.replace(",", "").strip())
    except (InvalidOperation, AttributeError):
        return None
    if value < 0:
        return None
    return int(value * (Decimal(10) ** decimals))


class MandateResolver:
    def __init__(self, registries: Registries, book: list[BookEntry], chain_id: int) -> None:
        self.reg = registries
        self.book = book
        self.chain_id = chain_id

    def _asset(self, symbol: str) -> str | None:
        s = symbol.strip().lower()
        if s in {"eth", "native"}:
            return NATIVE
        for t in self.reg.tokens.values():
            if t.symbol.lower() == s:
                return t.address
        return None

    def _spender(self, label: str) -> str | None:
        for addr, name in self.reg.spenders.items():
            if name.lower() == label.strip().lower() or addr == label.strip().lower():
                return checksum(addr)
        return None

    def resolve(
        self, draft: MandateDraft, prompt: str, now: datetime, ttl_s: int = 3600
    ) -> Mandate:
        unresolved = list(draft.unresolved)
        prompt_l = prompt.lower()

        recipients: list[RecipientRef] = []
        for r in draft.recipients:
            if r.address and r.address.lower() in prompt_l:
                recipients.append(RecipientRef(label=r.label, address=r.address, source="literal"))
                continue
            entry = next(
                (
                    e
                    for e in self.book
                    if e.trusted and e.label.strip().lower() == r.label.strip().lower()
                ),
                None,
            )
            if entry is not None:
                recipients.append(
                    RecipientRef(
                        label=entry.label,
                        address=entry.address,
                        source="book",
                        book_entry_id=entry.id,
                    )
                )
            else:
                unresolved.append(
                    f"recipient {r.label!r}" + (f" ({r.address})" if r.address else "")
                )

        assets: list[str] = []
        for sym in draft.assets:
            a = self._asset(sym)
            if a is None:
                unresolved.append(f"asset {sym!r}")
            elif a not in assets:
                assets.append(a)

        per_tx: dict[str, int] = {}
        session: dict[str, int] = {}
        for cap in draft.caps:
            a = self._asset(cap.asset)
            if a is None:
                unresolved.append(f"cap asset {cap.asset!r}")
                continue
            dec = self.reg.decimals(a)
            p = _units(cap.per_tx, dec) if cap.per_tx else None
            s = _units(cap.session, dec) if cap.session else None
            p = p if p is not None else s
            s = s if s is not None else p
            if p is None or s is None:
                unresolved.append(f"cap for {cap.asset!r}")
                continue
            per_tx[a], session[a] = p, s
            if a not in assets:
                assets.append(a)

        actions: list[ActionKind] = []
        for name in draft.allowed_actions:
            try:
                kind = ActionKind(name.strip().lower())
            except ValueError:
                unresolved.append(f"action {name!r}")
                continue
            if kind in (ActionKind.DELEGATE, ActionKind.UNKNOWN, ActionKind.BATCH):
                unresolved.append(f"action {name!r} (never allowed)")
                continue
            if kind not in actions:
                actions.append(kind)
        if not actions and recipients:
            actions = [ActionKind.TRANSFER]

        spenders = []
        for label in draft.spenders:
            addr = self._spender(label)
            if addr is None:
                unresolved.append(f"spender {label!r}")
            elif addr not in spenders:
                spenders.append(addr)

        approval_caps = []
        for ap in draft.approvals:
            addr, asset = self._spender(ap.spender), self._asset(ap.asset)
            amount = _units(ap.cap, self.reg.decimals(asset)) if asset else None
            if addr is None or asset is None or asset == NATIVE or amount is None:
                unresolved.append(f"approval {ap.spender!r}/{ap.asset!r}")
                continue
            approval_caps.append(ApprovalCap(spender=addr, token=asset, cap=amount))
            if addr not in spenders:
                spenders.append(addr)

        services = []
        for sv in draft.services:
            reg = self.reg.services.get(sv.service)
            per_request = _units(sv.per_request_cap, self.reg.decimals(reg.asset)) if reg else None
            if reg is None or per_request is None:
                unresolved.append(f"service {sv.service!r}")
                continue
            services.append(
                ServiceRef(
                    service=reg.service,
                    pay_to=reg.pay_to,
                    asset=reg.asset,
                    per_request_cap=per_request,
                )
            )
            if ActionKind.X402 not in actions:
                actions.append(ActionKind.X402)

        ttl = min(draft.expires_in_s or ttl_s, ttl_s, MAX_TTL_S)
        return Mandate(
            chain_ids=[self.chain_id],
            recipients=recipients,
            assets=assets,
            per_tx_cap=per_tx,
            session_cap=session,
            allowed_actions=actions,
            spenders=spenders,
            approval_caps=approval_caps,
            services=services,
            max_slippage_bps=draft.max_slippage_bps,
            expires_at=now + timedelta(seconds=ttl),
            constraints=draft.constraints,
            unresolved=unresolved,
        )
