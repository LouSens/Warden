"""The policy language (docs/policy.md §2): pydantic models for ``policy.yaml``."""

from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from warden.firewall.models import ActionKind, Severity, Verdict


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Defaults(Strict):
    verdict: Verdict = Verdict.BLOCK
    escalation_timeout_s: int = 600
    token_ttl_s: int = 120


class Params(Strict):
    lookalike_prefix: int = 4
    lookalike_suffix: int = 4
    dust_threshold_usd_equiv: Decimal = Decimal("0.01")
    permit_max_deadline_s: int = 3600
    transfer_tax_max_bps: int = 100


class Limits(Strict):
    auto_approve_max_usd_equiv: Decimal = Decimal("1000")
    session_cap_from: Literal["mandate"] = "mandate"


class When(Strict):
    finding: str | None = None
    finding_any: list[str] | None = None
    findings_max_severity: Severity | None = None
    mandate_satisfied: bool | None = None
    amount_over: str | None = None
    action: list[ActionKind] | None = None
    chain_id: list[int] | None = None


class Rule(Strict):
    id: str
    when: When
    then: Verdict


class Policy(Strict):
    version: Literal[1] = 1
    defaults: Defaults = Field(default_factory=Defaults)
    params: Params = Field(default_factory=Params)
    limits: Limits = Field(default_factory=Limits)
    rules: list[Rule]
