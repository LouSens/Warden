"""The firewall pipeline: decode → simulate → check → policy → intent → decision → token.

Invariant 3 is structural here: the only path to ``allow`` is the policy evaluator returning allow
(which the loader guarantees requires mandate satisfaction by rule); the judge's output is only ever
used to turn allow into escalate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from opentelemetry import trace

from warden.canonical import canonical_sha256
from warden.chain.history import HistoryIndex
from warden.chain.registry import Registries
from warden.checks.catalogue import outflow_usd, run_checks
from warden.checks.codes import Group
from warden.checks.context import CheckContext, declared_outflows
from warden.clock import Clock
from warden.decode.decoder import CallDecoder
from warden.firewall.models import (
    Action,
    ActionKind,
    DecidedBy,
    Decision,
    Effects,
    Finding,
    Origin,
    Proposal,
    Verdict,
)
from warden.firewall.reasons import reasons_for
from warden.firewall.store import FirewallStore, StoredDecision
from warden.ids import new_id
from warden.intent.judge import IntentJudge
from warden.intent.rules import mandate_satisfied
from warden.mandate.schema import Mandate
from warden.policy.evaluator import LoadedPolicy, PolicyInput, evaluate
from warden.simulate.simulator import Simulator, declared_effects
from warden.tokens import mint

tracer = trace.get_tracer("warden.firewall")


@dataclass(frozen=True)
class FirewallConfig:
    """Which stages run. ``passthrough`` is the benchmark's D0 baseline: record, then allow."""

    name: str
    groups: frozenset[Group] = frozenset()
    simulate: bool = False
    judge: bool = False
    passthrough: bool = False


CONFIGS: dict[str, FirewallConfig] = {
    "passthrough": FirewallConfig("passthrough", passthrough=True),
    "D3": FirewallConfig("D3", frozenset({"decoded"})),
    "D4": FirewallConfig("D4", frozenset({"decoded", "simulation"}), simulate=True),
    "D5": FirewallConfig(
        "D5", frozenset({"decoded", "simulation", "history"}), simulate=True, judge=True
    ),
}


class UnknownSession(KeyError):
    pass


@dataclass
class StageTimings:
    ms: dict[str, float] = field(default_factory=dict)


class Firewall:
    def __init__(
        self,
        *,
        store: FirewallStore,
        policy: LoadedPolicy,
        registries: Registries,
        clock: Clock,
        token_secret: bytes,
        simulator: Simulator | None = None,
        history: HistoryIndex | None = None,
        judge: IntentJudge | None = None,
        config: FirewallConfig = CONFIGS["D5"],
    ) -> None:
        if config.simulate and simulator is None:
            raise ValueError(f"{config.name} needs a simulator")
        self.store = store
        self.policy = policy
        self.registries = registries
        self.clock = clock
        self.token_secret = token_secret
        self.simulator = simulator
        self.history = history
        self.judge = judge
        self.config = config
        self.decoder = CallDecoder()
        self.last_timings = StageTimings()

    async def load_session(self, session_id: str) -> tuple[Mandate, dict[str, Any]]:
        session = await self.store.get_session(session_id)
        if session is None:
            raise UnknownSession(session_id)
        got = await self.store.get_mandate(session["mandate_id"])
        if got is None:
            raise UnknownSession(session_id)
        return got[0], session

    async def evaluate(
        self,
        session_id: str,
        proposal: Proposal,
        *,
        origin: Origin = Origin.API,
        idempotency_key: str | None = None,
    ) -> Decision:
        timings = StageTimings()
        now = self.clock.now()
        mandate, _ = await self.load_session(session_id)
        await self.store.ensure_policy(self.policy.sha256, self.policy.text, now)
        raw_sha = canonical_sha256(proposal.model_dump(mode="json"))

        with tracer.start_as_current_span("firewall.proposal") as span:
            span.set_attribute("kind", proposal.kind.value)
            span.set_attribute("firewall.config", self.config.name)
            pid = await self.store.insert_proposal(
                session_id, proposal, origin, raw_sha, now, idempotency_key
            )
            span.set_attribute("proposal_id", pid)

            t0 = time.perf_counter()
            with tracer.start_as_current_span("decode"):
                action = self.decoder.decode(proposal)
            timings.ms["decode"] = (time.perf_counter() - t0) * 1000

            effects: Effects | None = None
            t0 = time.perf_counter()
            if self.config.simulate and self.simulator is not None:
                with tracer.start_as_current_span("simulate"):
                    effects = await self.simulator.simulate(proposal, action)
            elif proposal.kind.value != "tx":
                effects = declared_effects(action)
            timings.ms["simulate"] = (time.perf_counter() - t0) * 1000

            t0 = time.perf_counter()
            history_view = None
            if "history" in self.config.groups and self.history is not None:
                history_view = await self.history.refresh()
            ctx = CheckContext(
                proposal=proposal,
                action=action,
                mandate=mandate,
                registries=self.registries,
                params=self.policy.policy.params,
                now=now,
                sender=proposal.sender,
                effects=effects,
                spent=await self.store.spent(session_id),
                book=await self.store.book(proposal.chain_id),
                history=history_view,
                used_x402_nonces=await self.store.used_x402_nonces(),
            )
            with tracer.start_as_current_span("checks"):
                findings = (
                    [] if self.config.passthrough else run_checks(ctx, set(self.config.groups))
                )
            timings.ms["checks"] = (time.perf_counter() - t0) * 1000

            satisfied = mandate_satisfied(findings)
            t0 = time.perf_counter()
            if self.config.passthrough:
                verdict, matched, deciding = Verdict.ALLOW, ["passthrough"], ["passthrough"]
            else:
                result = evaluate(
                    self.policy.policy,
                    PolicyInput(
                        findings=findings,
                        mandate_satisfied=satisfied,
                        outflow_usd=outflow_usd(ctx),
                        action_kinds={leaf.kind for leaf in action.leaves()},
                        chain_id=proposal.chain_id,
                    ),
                )
                verdict, matched, deciding = (
                    result.verdict,
                    result.matched_rules,
                    result.deciding_rules,
                )
            timings.ms["policy"] = (time.perf_counter() - t0) * 1000

            decided_by = DecidedBy.RULES
            judge_json: dict[str, Any] | None = None
            if (
                verdict is Verdict.ALLOW
                and self.config.judge
                and self.judge is None
                and mandate.constraints
            ):
                # Constraints the rules cannot check and no judge to check them: do not allow.
                verdict, decided_by = Verdict.ESCALATE, DecidedBy.JUDGE
                judge_json = {"verdict": "unsure", "reason": "no intent judge configured"}
            if (
                verdict is Verdict.ALLOW
                and self.config.judge
                and self.judge is not None
                and mandate.constraints
            ):
                t0 = time.perf_counter()
                with tracer.start_as_current_span("judge"):
                    jr = await self.judge.judge(mandate.constraints, action, effects)
                timings.ms["judge"] = (time.perf_counter() - t0) * 1000
                judge_json = {
                    "verdict": jr.verdict,
                    "reason": jr.reason,
                    "model": jr.model,
                    "tokens_in": jr.tokens_in,
                    "tokens_out": jr.tokens_out,
                }
                if jr.verdict != "consistent":
                    verdict, decided_by = Verdict.ESCALATE, DecidedBy.JUDGE

            await self.store.record_analysis(pid, action, effects, findings)
            reasons = reasons_for(verdict, findings, action, self.registries, deciding)
            if judge_json is not None and decided_by is DecidedBy.JUDGE:
                reasons.append(f"Intent check: {judge_json['reason']}")

            minted = await self._decide(
                pid=pid,
                proposal=proposal,
                raw_sha=raw_sha,
                verdict=verdict,
                decided_by=decided_by,
                matched=matched,
                reasons=reasons,
                mandate=mandate,
                now=now,
                judge_json=judge_json,
            )
            if verdict is Verdict.ALLOW:
                await self.store.add_spent(session_id, ctx.outflows())
            span.set_attribute("verdict", verdict.value)
            self.last_timings = timings
            return minted.to_decision(
                action=action,
                effects=effects,
                findings=findings,
                satisfied=satisfied,
                policy_sha256=self.policy.sha256,
                mandate_sha256=mandate.sha256,
            )

    async def _decide(
        self,
        *,
        pid: str,
        proposal: Proposal,
        raw_sha: str,
        verdict: Verdict,
        decided_by: DecidedBy,
        matched: list[str],
        reasons: list[str],
        mandate: Mandate,
        now: datetime,
        judge_json: dict[str, Any] | None,
        supersedes_id: str | None = None,
    ) -> _Minted:
        did = new_id("dec")
        token = payload = None
        if verdict is Verdict.ALLOW:
            ttl = self.policy.policy.defaults.token_ttl_s
            token, payload = mint(
                self.token_secret,
                decision_id=did,
                proposal_sha256=raw_sha,
                chain_id=proposal.chain_id,
                expires_at=now + timedelta(seconds=ttl),
            )
        stored = await self.store.append_decision(
            proposal_id=pid,
            verdict=verdict,
            decided_by=decided_by,
            matched_rules=matched,
            reasons=reasons,
            policy_sha256=self.policy.sha256,
            mandate_sha256=mandate.sha256,
            now=now,
            judge=judge_json,
            token_nonce=payload.nonce if payload else None,
            token_expires_at=payload.expires_at if payload else None,
            supersedes_id=supersedes_id,
            decision_id=did,
        )
        approval_id = None
        if verdict is Verdict.ESCALATE:
            timeout = self.policy.policy.defaults.escalation_timeout_s
            approval_id = await self.store.create_approval(
                stored.id, now, now + timedelta(seconds=timeout)
            )
        return _Minted(stored, token, payload.expires_at if payload else None, approval_id)

    # ------------------------------------------------------------------ approvals
    async def resolve_approval(
        self, approval_id: str, *, approve: bool, resolver: str = "user", note: str | None = None
    ) -> Decision:
        """Human (or simulated approver) decision on an escalation. Approving can only follow an
        escalation, never override a block."""
        now = self.clock.now()
        approval = await self.store.get_approval(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        state = "approved" if approve else "denied"
        if not await self.store.resolve_approval(approval_id, state, now, resolver, note):
            raise ApprovalResolved(approval_id)
        return await self._supersede(
            approval["decision_id"],
            Verdict.ALLOW if approve else Verdict.BLOCK,
            DecidedBy.HUMAN,
            f"{'Approved' if approve else 'Denied'} by {resolver}" + (f": {note}" if note else "."),
            now,
        )

    async def expire_approvals(self) -> list[Decision]:
        now = self.clock.now()
        out = []
        for a in await self.store.due_approvals(now):
            if await self.store.resolve_approval(a["id"], "expired", now, "timeout", None):
                out.append(
                    await self._supersede(
                        a["decision_id"],
                        Verdict.BLOCK,
                        DecidedBy.TIMEOUT,
                        "Escalation timed out (default deny).",
                        now,
                    )
                )
        return out

    async def _supersede(
        self, escalated_id: str, verdict: Verdict, decided_by: DecidedBy, reason: str, now: datetime
    ) -> Decision:
        prior = await self.store.get_decision(escalated_id)
        if prior is None:
            raise KeyError(escalated_id)
        record = await self.store.proposal_record(prior.proposal_id)
        assert record is not None
        proposal = Proposal.model_validate(record["proposal"]["raw"])
        session_id = record["proposal"]["session_id"]
        mandate, _ = await self.load_session(session_id)
        minted = await self._decide(
            pid=prior.proposal_id,
            proposal=proposal,
            raw_sha=record["proposal"]["raw_sha256"],
            verdict=verdict,
            decided_by=decided_by,
            matched=prior.matched_rules,
            reasons=[*prior.reasons, reason],
            mandate=mandate,
            now=now,
            judge_json=None,
            supersedes_id=prior.id,
        )
        action = (
            Action.model_validate(record["action"])
            if record["action"]
            else Action(kind=ActionKind.UNKNOWN)
        )
        effects = Effects.model_validate(record["effects"]) if record["effects"] else None
        if verdict is Verdict.ALLOW:
            outflows = (
                effects.outflows_of(proposal.sender)
                if effects is not None
                else declared_outflows(action, proposal.sender)
            )
            await self.store.add_spent(session_id, outflows)
        findings = [Finding.model_validate(f) for f in record["findings"]]
        return minted.to_decision(
            action=action,
            effects=effects,
            findings=findings,
            satisfied=False,
            policy_sha256=self.policy.sha256,
            mandate_sha256=mandate.sha256,
        )


@dataclass(frozen=True)
class _Minted:
    stored: StoredDecision
    token: str | None
    token_expires_at: str | None
    approval_id: str | None

    def to_decision(
        self,
        *,
        action: Action,
        effects: Effects | None,
        findings: list[Finding],
        satisfied: bool,
        policy_sha256: str,
        mandate_sha256: str,
    ) -> Decision:
        s = self.stored
        return Decision(
            proposal_id=s.proposal_id,
            decision_id=s.id,
            verdict=s.verdict,
            decided_by=s.decided_by,
            matched_rules=s.matched_rules,
            reasons=s.reasons,
            action=action,
            effects=effects,
            findings=findings,
            mandate_satisfied=satisfied,
            policy_sha256=policy_sha256,
            mandate_sha256=mandate_sha256,
            approval_id=self.approval_id,
            decision_token=self.token,
            token_expires_at=self.token_expires_at,
        )


class ApprovalResolved(RuntimeError):
    pass
