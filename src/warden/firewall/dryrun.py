"""Policy impact dry-run: re-evaluate recorded proposals under a candidate policy.

Uses the stored action, effects and findings (no new simulation). Parameter-only changes to checks
are not re-run here; the report says so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from warden.chain.registry import Registries
from warden.checks.context import declared_outflows
from warden.firewall.models import NATIVE, Action, Effects, Finding, Verdict
from warden.firewall.store import FirewallStore
from warden.intent.rules import mandate_satisfied
from warden.policy.evaluator import LoadedPolicy, PolicyInput, evaluate


@dataclass(frozen=True)
class Change:
    proposal_id: str
    old: str
    new: str
    rules: list[str]


async def dry_run(
    store: FirewallStore, candidate: LoadedPolicy, registries: Registries
) -> dict[str, Any]:
    rows = await store.db.fetchall(
        "SELECT p.id, p.chain_id, p.raw_json, a.action_json, s.effects_json FROM proposal p "
        "JOIN action a ON a.proposal_id = p.id LEFT JOIN simulation s ON s.proposal_id = p.id "
        "ORDER BY p.created_at"
    )
    changes: list[Change] = []
    counts: dict[str, int] = {}
    for r in rows:
        first = await store.db.fetchone(
            "SELECT verdict, decided_by FROM decision WHERE proposal_id=? ORDER BY seq LIMIT 1",
            (r["id"],),
        )
        if first is None or first["decided_by"] not in ("rules", "judge"):
            continue
        findings = [
            Finding(code=f["code"], severity=f["severity"], evidence={})
            for f in await store.db.fetchall(
                "SELECT code, severity FROM finding WHERE proposal_id=?", (r["id"],)
            )
        ]
        action = Action.model_validate_json(r["action_json"])
        effects = Effects.model_validate_json(r["effects_json"]) if r["effects_json"] else None
        sender = json.loads(r["raw_json"])["payload"].get("from", "")
        outflows = (
            effects.outflows_of(sender)
            if effects and effects.mode != "declared"
            else declared_outflows(action, sender)
        )
        usd: Decimal | None = Decimal(0)
        for asset, amount in outflows.items():
            v = registries.usd_value(NATIVE if asset == NATIVE else asset, amount)
            if v is None:
                usd = None
                break
            usd = (usd or Decimal(0)) + v
        result = evaluate(
            candidate.policy,
            PolicyInput(
                findings=findings,
                mandate_satisfied=mandate_satisfied(findings),
                outflow_usd=usd,
                action_kinds={leaf.kind for leaf in action.leaves()},
                chain_id=int(r["chain_id"]),
            ),
        )
        old = Verdict(first["verdict"])
        if result.verdict is not old:
            changes.append(Change(r["id"], old.value, result.verdict.value, result.deciding_rules))
            key = f"{old.value}->{result.verdict.value}"
            counts[key] = counts.get(key, 0) + 1
    return {
        "sha256": candidate.sha256,
        "evaluated": len(rows),
        "changed": [c.__dict__ for c in changes],
        "counts": counts,
        "note": "stored findings reused; parameter changes to checks are not re-simulated",
    }
