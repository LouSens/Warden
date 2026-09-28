"""Load, validate and evaluate policies. Pure: no I/O besides parsing text, no LLM, no chain."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

import yaml
from pydantic import ValidationError

from warden.canonical import sha256_hex
from warden.checks.codes import CHECK_CODES
from warden.firewall.models import ActionKind, Finding, Verdict
from warden.policy.schema import Policy, Rule


class PolicyInvalid(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class LoadedPolicy:
    policy: Policy
    sha256: str
    text: str


def validate_policy(policy: Policy) -> list[str]:
    """Static safety properties the loader enforces (docs/policy.md §2.3)."""
    errors: list[str] = []
    if policy.defaults.verdict is not Verdict.BLOCK:
        errors.append("defaults.verdict must be block (default deny)")
    seen: set[str] = set()
    limit_names = set(type(policy.limits).model_fields)
    for rule in policy.rules:
        if rule.id in seen:
            errors.append(f"duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        w = rule.when
        if rule.then is Verdict.ALLOW and w.mandate_satisfied is not True:
            errors.append(f"rule {rule.id!r}: allow requires mandate_satisfied: true")
        codes = ([w.finding] if w.finding else []) + (w.finding_any or [])
        for code in codes:
            if code not in CHECK_CODES:
                errors.append(f"rule {rule.id!r}: unknown check code {code!r}")
        if w.amount_over is not None and w.amount_over not in limit_names:
            errors.append(f"rule {rule.id!r}: unknown limit {w.amount_over!r}")
        if not any(v is not None for v in w.model_dump().values()):
            errors.append(f"rule {rule.id!r}: empty when")
    return errors


def load_policy(text: str) -> LoadedPolicy:
    try:
        data = yaml.safe_load(text)
        policy = Policy.model_validate(data)
    except (yaml.YAMLError, ValidationError) as exc:
        raise PolicyInvalid([str(exc)[:1500]]) from exc
    errors = validate_policy(policy)
    if errors:
        raise PolicyInvalid(errors)
    return LoadedPolicy(policy, sha256_hex(text.replace("\r\n", "\n")), text)


@dataclass(frozen=True)
class PolicyInput:
    findings: list[Finding]
    mandate_satisfied: bool
    outflow_usd: Decimal | None  # None = contains an outflow with no trusted price
    action_kinds: set[ActionKind]
    chain_id: int


@dataclass(frozen=True)
class PolicyResult:
    verdict: Verdict
    matched_rules: list[str] = field(default_factory=list)
    deciding_rules: list[str] = field(default_factory=list)


def _holds(rule: Rule, inp: PolicyInput, policy: Policy) -> bool:
    w = rule.when
    codes = {f.code for f in inp.findings}
    if w.finding is not None and w.finding not in codes:
        return False
    if w.finding_any is not None and not codes.intersection(w.finding_any):
        return False
    if w.findings_max_severity is not None and any(
        f.severity.rank > w.findings_max_severity.rank for f in inp.findings
    ):
        return False
    if w.mandate_satisfied is not None and w.mandate_satisfied != inp.mandate_satisfied:
        return False
    if w.amount_over is not None:
        limit = getattr(policy.limits, w.amount_over)
        if inp.outflow_usd is not None and inp.outflow_usd <= Decimal(limit):
            return False
    if w.action is not None and not inp.action_kinds.intersection(w.action):
        return False
    return not (w.chain_id is not None and inp.chain_id not in w.chain_id)


def evaluate(policy: Policy, inp: PolicyInput) -> PolicyResult:
    """Precedence block > escalate > allow; nothing matched -> defaults.verdict (block)."""
    matched = [r for r in policy.rules if _holds(r, inp, policy)]
    for verdict in (Verdict.BLOCK, Verdict.ESCALATE, Verdict.ALLOW):
        deciding = [r.id for r in matched if r.then is verdict]
        if deciding:
            return PolicyResult(verdict, [r.id for r in matched], deciding)
    return PolicyResult(policy.defaults.verdict, [], [])
