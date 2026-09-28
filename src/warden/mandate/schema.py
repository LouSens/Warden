"""The mandate: an immutable, structured statement of what the user asked for.

Created only from the trusted channel (invariant 2). See docs/agents.md §2.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from warden.canonical import canonical_sha256
from warden.chain.abi import checksum
from warden.chains import require_allowed
from warden.firewall.models import NATIVE, ActionKind, Amount


class RecipientRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    label: str
    address: str
    source: Literal["literal", "book", "history"]
    book_entry_id: str | None = None

    @field_validator("address")
    @classmethod
    def _cs(cls, v: str) -> str:
        return checksum(v)


class ServiceRef(BaseModel):
    """An x402 service the user allows paying, with its registered payee and a per-request cap."""

    model_config = ConfigDict(frozen=True)

    service: str
    pay_to: str
    asset: str  # token address
    per_request_cap: Amount

    @field_validator("pay_to", "asset")
    @classmethod
    def _cs(cls, v: str) -> str:
        return checksum(v)


class ApprovalCap(BaseModel):
    model_config = ConfigDict(frozen=True)

    spender: str
    token: str
    cap: Amount

    @field_validator("spender", "token")
    @classmethod
    def _cs(cls, v: str) -> str:
        return checksum(v)


class Mandate(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: Literal[1] = 1
    chain_ids: list[int]
    recipients: list[RecipientRef] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)  # token addresses or "native"
    per_tx_cap: dict[str, Amount] = Field(default_factory=dict)  # asset -> base units
    session_cap: dict[str, Amount] = Field(default_factory=dict)
    allowed_actions: list[ActionKind] = Field(default_factory=list)
    spenders: list[str] = Field(default_factory=list)
    approval_caps: list[ApprovalCap] = Field(default_factory=list)
    services: list[ServiceRef] = Field(default_factory=list)
    max_slippage_bps: int | None = None
    delegation: Literal["forbidden"] = "forbidden"
    expires_at: datetime
    constraints: list[str] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)

    @field_validator("chain_ids")
    @classmethod
    def _chains(cls, v: list[int]) -> list[int]:
        if not v:
            raise ValueError("a mandate needs at least one chain id")
        return [require_allowed(c) for c in v]

    @field_validator("assets")
    @classmethod
    def _assets(cls, v: list[str]) -> list[str]:
        return [a if a == NATIVE else checksum(a) for a in v]

    @field_validator("per_tx_cap", "session_cap")
    @classmethod
    def _cap_keys(cls, v: dict[str, int]) -> dict[str, int]:
        return {(k if k == NATIVE else checksum(k)): amt for k, amt in v.items()}

    @field_validator("spenders")
    @classmethod
    def _spenders(cls, v: list[str]) -> list[str]:
        return [checksum(a) for a in v]

    @field_validator("allowed_actions")
    @classmethod
    def _no_delegate(cls, v: list[ActionKind]) -> list[ActionKind]:
        if ActionKind.DELEGATE in v:
            raise ValueError("delegation is always forbidden in v0.1")
        return v

    # ------------------------------------------------------------------ helpers
    @property
    def sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    def recipient_addresses(self) -> set[str]:
        return {r.address.lower() for r in self.recipients}

    def spender_addresses(self) -> set[str]:
        return {s.lower() for s in self.spenders}

    def cap_for(self, asset: str, which: Literal["per_tx", "session"]) -> int:
        caps = self.per_tx_cap if which == "per_tx" else self.session_cap
        for k, v in caps.items():
            if k.lower() == asset.lower():
                return v
        return 0  # an asset without a cap may not leave the wallet

    def approval_cap(self, spender: str, token: str) -> int:
        for c in self.approval_caps:
            if c.spender.lower() == spender.lower() and c.token.lower() == token.lower():
                return c.cap
        return self.cap_for(token, "per_tx")

    def service_by_name(self, name: str | None) -> ServiceRef | None:
        return next((s for s in self.services if s.service == name), None)
