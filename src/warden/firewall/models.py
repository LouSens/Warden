"""Types that flow through the firewall pipeline: proposals, actions, effects, findings, decisions.

Amounts are Python ints in base units internally and decimal strings on the wire (pydantic
serialises ``Amount`` as a string).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer, field_validator

Amount = Annotated[int, PlainSerializer(lambda v: str(v), return_type=str, when_used="json")]

MAX_UINT256 = 2**256 - 1
UNLIMITED_THRESHOLD = 2**255
NATIVE = "native"


class ProposalKind(StrEnum):
    TX = "tx"
    TYPED_DATA = "typed_data"
    AUTH_7702 = "7702_auth"
    X402 = "x402_payment"


class Origin(StrEnum):
    AGENT = "agent"
    MCP = "mcp"
    API = "api"


class Proposal(BaseModel):
    """What an agent (or MCP client, or API caller) asks Warden to allow."""

    model_config = ConfigDict(frozen=True)

    kind: ProposalKind
    chain_id: int
    payload: dict[str, Any]

    @property
    def sender(self) -> str:
        return str(self.payload.get("from", ""))


class ActionKind(StrEnum):
    TRANSFER = "transfer"  # ERC-20 transfer or native value transfer (token = "native")
    APPROVE = "approve"
    PERMIT = "permit"  # EIP-2612 typed data
    PERMIT2 = "permit2"  # Permit2 typed data
    SET_APPROVAL_FOR_ALL = "set_approval_for_all"
    SWAP = "swap"
    DELEGATE = "delegate"  # EIP-7702 authorization
    X402 = "x402"  # EIP-3009 payment for an x402 resource
    BATCH = "batch"
    UNKNOWN = "unknown"


class Action(BaseModel):
    """A decoded proposal. ``batch`` actions carry ``children``; every other kind is a leaf."""

    kind: ActionKind
    target: str | None = None  # contract called (or recipient of a native transfer)
    token: str | None = None  # token address, or "native"
    to: str | None = None  # destination of value
    amount: Amount | None = None
    owner: str | None = None
    spender: str | None = None
    approved: bool | None = None
    deadline: int | None = None
    token_in: str | None = None
    token_out: str | None = None
    amount_in: Amount | None = None
    min_out: Amount | None = None
    delegate: str | None = None
    service: str | None = None
    nonce: str | None = None
    selector: str | None = None
    note: str | None = None
    children: list[Action] = Field(default_factory=list)

    def leaves(self) -> list[Action]:
        if self.kind is ActionKind.BATCH:
            return [leaf for child in self.children for leaf in child.leaves()]
        return [self]


class AssetDelta(BaseModel):
    address: str
    token: str  # token address or "native"
    delta: Amount


class AllowanceDelta(BaseModel):
    owner: str
    spender: str
    token: str
    before: Amount
    after: Amount


class DelegationDelta(BaseModel):
    account: str
    delegate: str


class Effects(BaseModel):
    """What a proposal does (simulated) or declares it will do (typed data, D3)."""

    mode: Literal["local", "fork", "declared"]
    reverted: bool = False
    revert_reason: str | None = None
    gas_used: int | None = None
    block_number: int = 0
    duration_ms: int = 0
    assets: list[AssetDelta] = Field(default_factory=list)
    allowances: list[AllowanceDelta] = Field(default_factory=list)
    delegations: list[DelegationDelta] = Field(default_factory=list)
    honeypot_sell_reverted: bool | None = None
    transfer_tax_bps: int | None = None

    def outflows_of(self, address: str) -> dict[str, int]:
        """Net outflow per token for ``address`` (positive numbers)."""
        out: dict[str, int] = {}
        a = address.lower()
        for d in self.assets:
            if d.address.lower() == a and d.delta < 0:
                out[d.token.lower()] = out.get(d.token.lower(), 0) - d.delta
        return out

    def inflows(self) -> dict[str, dict[str, int]]:
        """Positive deltas per address per token."""
        out: dict[str, dict[str, int]] = {}
        for d in self.assets:
            if d.delta > 0:
                per = out.setdefault(d.address.lower(), {})
                per[d.token.lower()] = per.get(d.token.lower(), 0) + d.delta
        return out


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Finding(BaseModel):
    code: str
    severity: Severity
    evidence: dict[str, Any] = Field(default_factory=dict)


class Verdict(StrEnum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    BLOCK = "block"


class DecidedBy(StrEnum):
    RULES = "rules"
    JUDGE = "judge"
    HUMAN = "human"
    TIMEOUT = "timeout"


class Decision(BaseModel):
    """The API/agent-facing result of evaluating a proposal."""

    proposal_id: str
    decision_id: str
    verdict: Verdict
    decided_by: DecidedBy
    matched_rules: list[str]
    reasons: list[str]
    action: Action
    effects: Effects | None
    findings: list[Finding]
    mandate_satisfied: bool
    policy_sha256: str
    mandate_sha256: str
    approval_id: str | None = None
    decision_token: str | None = None
    token_expires_at: str | None = None

    @field_validator("decision_token")
    @classmethod
    def _token_only_on_allow(cls, v: str | None, info: Any) -> str | None:
        if v is not None and info.data.get("verdict") is not Verdict.ALLOW:
            raise ValueError("a decision token exists only for allow")
        return v

    def for_agent(self) -> dict[str, Any]:
        """What an agent tool may see: never the token, never raw effects evidence it did not ask for."""
        return {
            "proposal_id": self.proposal_id,
            "verdict": self.verdict.value,
            "reasons": self.reasons,
            "codes": [f.code for f in self.findings],
            "approval_id": self.approval_id,
        }
