"""Inputs every check reads. Built once per proposal by the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from warden.chain.registry import Registries
from warden.firewall.models import NATIVE, Action, ActionKind, Effects, Proposal
from warden.mandate.schema import Mandate
from warden.policy.schema import Params


@dataclass(frozen=True)
class BookEntry:
    id: str
    label: str
    address: str
    provenance: Literal["user", "agent", "import"]
    verified: bool

    @property
    def trusted(self) -> bool:
        return self.verified and self.provenance in ("user", "import")


@dataclass(frozen=True)
class HistoryView:
    """The user EOA's history. ``own_destinations`` come only from transactions the user signed;
    ``log_only`` are addresses seen only in Transfer logs (forgeable), with the largest value seen in
    reference-USD terms (None if the token has no trusted price)."""

    own_destinations: frozenset[str] = frozenset()
    log_only: dict[str, float | None] = field(default_factory=dict)


@dataclass
class CheckContext:
    proposal: Proposal
    action: Action
    mandate: Mandate
    registries: Registries
    params: Params
    now: datetime
    sender: str
    effects: Effects | None = None  # None when the configuration does not simulate
    spent: dict[str, int] = field(default_factory=dict)  # lower asset -> base units this session
    book: list[BookEntry] = field(default_factory=list)
    history: HistoryView | None = None
    used_x402_nonces: frozenset[str] = frozenset()

    @property
    def leaves(self) -> list[Action]:
        return self.action.leaves()

    @property
    def simulated(self) -> bool:
        return self.effects is not None and self.effects.mode != "declared"

    def declared_outflows(self) -> dict[str, int]:
        """Outflows of the sender that the decoded action itself declares, per lower asset."""
        return declared_outflows(self.action, self.sender)

    def outflows(self) -> dict[str, int]:
        """Simulated outflows when available, otherwise declared ones."""
        if self.simulated and self.effects is not None:
            return self.effects.outflows_of(self.sender)
        return self.declared_outflows()

    def value_destinations(self) -> list[tuple[str, Action]]:
        """Addresses value is sent to (transfers and x402 payments), with the leaf that sends it."""
        dests = []
        for leaf in self.leaves:
            if leaf.kind in (ActionKind.TRANSFER, ActionKind.X402) and leaf.to:
                dests.append((leaf.to, leaf))
        return dests

    def tokens_touched(self) -> set[str]:
        toks: set[str] = set()
        for leaf in self.leaves:
            for t in (leaf.token, leaf.token_in, leaf.token_out):
                if t and t != NATIVE:
                    toks.add(t)
        return toks

    def known_counterparties(self) -> dict[str, str]:
        """lower address -> label, for lookalike comparison and first-seen exemption."""
        known: dict[str, str] = {}
        for r in self.mandate.recipients:
            known[r.address.lower()] = f"{r.label} (mandate)"
        for e in self.book:
            if e.trusted:
                known[e.address.lower()] = f"{e.label} (book, verified)"
        for s in self.registries.services.values():
            known[s.pay_to.lower()] = f"{s.service} (service registry)"
        for addr in self.registries.spenders:
            known[addr] = self.registries.spenders[addr]
        if self.history is not None:
            for a in self.history.own_destinations:
                known.setdefault(a, "past payment")
        return known


def declared_outflows(action: Action, sender: str) -> dict[str, int]:
    """Outflows of ``sender`` declared by a decoded action, per lower-cased asset."""
    out: dict[str, int] = {}
    s = sender.lower()

    def add(asset: str, amount: int) -> None:
        key = asset.lower()
        out[key] = out.get(key, 0) + amount

    for leaf in action.leaves():
        if leaf.kind in (ActionKind.TRANSFER, ActionKind.X402) and leaf.amount:
            owner = (leaf.owner or sender).lower()
            if owner == s and leaf.token:
                add(leaf.token, leaf.amount)
        elif leaf.kind is ActionKind.SWAP and leaf.token_in and leaf.amount_in:
            add(leaf.token_in, leaf.amount_in)
    return out
