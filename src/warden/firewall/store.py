"""Persistence for the firewall: mandates, sessions, proposals, the decision log, approvals and the
address book. The decision log is append-only (SQL triggers) and hash-chained (this module)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from warden.canonical import canonical_json, sha256_hex
from warden.checks.context import BookEntry
from warden.clock import iso
from warden.firewall.models import (
    Action,
    DecidedBy,
    Effects,
    Finding,
    Origin,
    Proposal,
    Verdict,
)
from warden.ids import new_id
from warden.mandate.schema import Mandate
from warden.storage.database import Database

GENESIS_HASH = "0" * 64

_DECISION_COLUMNS = (
    "id",
    "seq",
    "proposal_id",
    "supersedes_id",
    "verdict",
    "decided_by",
    "matched_rules",
    "reasons_json",
    "policy_sha256",
    "mandate_sha256",
    "judge_json",
    "token_nonce",
    "token_expires_at",
    "created_at",
    "prev_hash",
)


def row_hash(row: dict[str, Any]) -> str:
    body = {k: row[k] for k in _DECISION_COLUMNS}
    return sha256_hex(str(row["prev_hash"]).encode() + canonical_json(body))


@dataclass(frozen=True)
class StoredDecision:
    id: str
    seq: int
    proposal_id: str
    verdict: Verdict
    decided_by: DecidedBy
    matched_rules: list[str]
    reasons: list[str]
    policy_sha256: str
    mandate_sha256: str
    token_nonce: str | None
    token_expires_at: str | None
    created_at: str
    supersedes_id: str | None


def _decision(row: Any) -> StoredDecision:
    return StoredDecision(
        id=row["id"],
        seq=int(row["seq"]),
        proposal_id=row["proposal_id"],
        verdict=Verdict(row["verdict"]),
        decided_by=DecidedBy(row["decided_by"]),
        matched_rules=json.loads(row["matched_rules"]),
        reasons=json.loads(row["reasons_json"]),
        policy_sha256=row["policy_sha256"],
        mandate_sha256=row["mandate_sha256"],
        token_nonce=row["token_nonce"],
        token_expires_at=row["token_expires_at"],
        created_at=row["created_at"],
        supersedes_id=row["supersedes_id"],
    )


class FirewallStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------ policy
    async def ensure_policy(self, sha256: str, text: str, now: datetime) -> None:
        await self.db.execute(
            "INSERT OR IGNORE INTO policy_version(sha256, yaml, loaded_at) VALUES (?,?,?)",
            (sha256, text, iso(now)),
        )

    async def policy_text(self, sha256: str) -> str | None:
        v = await self.db.scalar("SELECT yaml FROM policy_version WHERE sha256=?", (sha256,))
        return None if v is None else str(v)

    # ------------------------------------------------------------------ mandates / sessions
    async def insert_mandate(
        self,
        mandate: Mandate,
        *,
        prompt_sha256: str,
        now: datetime,
        extractor_model: str | None = None,
        prompt_version: str | None = None,
    ) -> str:
        existing = await self.db.scalar(
            "SELECT id FROM mandate WHERE body_sha256=?", (mandate.sha256,)
        )
        if existing is not None:
            return str(existing)
        mid = new_id("man")
        await self.db.execute(
            "INSERT INTO mandate VALUES (?,?,?,?,?,?,?,?)",
            (
                mid,
                iso(now),
                iso(mandate.expires_at),
                prompt_sha256,
                canonical_json(mandate.model_dump(mode="json")).decode(),
                mandate.sha256,
                extractor_model,
                prompt_version,
            ),
        )
        return mid

    async def get_mandate(self, mandate_id: str) -> tuple[Mandate, dict[str, Any]] | None:
        row = await self.db.fetchone("SELECT * FROM mandate WHERE id=?", (mandate_id,))
        if row is None:
            return None
        return Mandate.model_validate_json(row["body_json"]), dict(row)

    async def create_session(self, mandate_id: str, now: datetime) -> str:
        sid = new_id("ses")
        await self.db.execute(
            "INSERT INTO session VALUES (?,?,?,?)", (sid, mandate_id, iso(now), "{}")
        )
        return sid

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        row = await self.db.fetchone("SELECT * FROM session WHERE id=?", (session_id,))
        return dict(row) if row is not None else None

    async def spent(self, session_id: str) -> dict[str, int]:
        raw = await self.db.scalar("SELECT spent_json FROM session WHERE id=?", (session_id,))
        return {k: int(v) for k, v in json.loads(raw or "{}").items()}

    async def add_spent(self, session_id: str, outflows: dict[str, int]) -> None:
        spent = await self.spent(session_id)
        for asset, amount in outflows.items():
            spent[asset] = spent.get(asset, 0) + amount
        await self.db.execute(
            "UPDATE session SET spent_json=? WHERE id=?",
            (json.dumps({k: str(v) for k, v in spent.items()}), session_id),
        )

    # ------------------------------------------------------------------ proposals
    async def find_by_idempotency_key(self, key: str) -> str | None:
        v = await self.db.scalar("SELECT id FROM proposal WHERE idempotency_key=?", (key,))
        return None if v is None else str(v)

    async def insert_proposal(
        self,
        session_id: str,
        proposal: Proposal,
        origin: Origin,
        raw_sha256: str,
        now: datetime,
        idempotency_key: str | None = None,
    ) -> str:
        pid = new_id("prp")
        await self.db.execute(
            "INSERT INTO proposal VALUES (?,?,?,?,?,?,?,?,?)",
            (
                pid,
                session_id,
                proposal.kind.value,
                proposal.chain_id,
                origin.value,
                canonical_json(proposal.model_dump(mode="json")).decode(),
                raw_sha256,
                idempotency_key,
                iso(now),
            ),
        )
        return pid

    async def record_analysis(
        self, proposal_id: str, action: Action, effects: Effects | None, findings: list[Finding]
    ) -> None:
        await self.db.execute(
            "INSERT INTO action VALUES (?,?)", (proposal_id, action.model_dump_json())
        )
        if effects is not None:
            await self.db.execute(
                "INSERT INTO simulation VALUES (?,?,?,?,?,?,?)",
                (
                    proposal_id,
                    effects.block_number,
                    effects.mode,
                    effects.model_dump_json(),
                    int(effects.reverted),
                    effects.gas_used,
                    effects.duration_ms,
                ),
            )
        await self.db.executemany(
            "INSERT INTO finding(proposal_id, code, severity, evidence_json) VALUES (?,?,?,?)",
            [
                (proposal_id, f.code, f.severity.value, json.dumps(f.evidence, default=str))
                for f in findings
            ],
        )

    async def proposal_record(self, proposal_id: str) -> dict[str, Any] | None:
        row = await self.db.fetchone("SELECT * FROM proposal WHERE id=?", (proposal_id,))
        if row is None:
            return None
        action = await self.db.fetchone(
            "SELECT action_json FROM action WHERE proposal_id=?", (proposal_id,)
        )
        sim = await self.db.fetchone(
            "SELECT effects_json FROM simulation WHERE proposal_id=?", (proposal_id,)
        )
        findings = await self.db.fetchall(
            "SELECT code, severity, evidence_json FROM finding WHERE proposal_id=? ORDER BY id",
            (proposal_id,),
        )
        decisions = await self.db.fetchall(
            "SELECT * FROM decision WHERE proposal_id=? ORDER BY seq", (proposal_id,)
        )
        return {
            "proposal": dict(row) | {"raw": json.loads(row["raw_json"])},
            "action": json.loads(action["action_json"]) if action else None,
            "effects": json.loads(sim["effects_json"]) if sim else None,
            "findings": [
                {
                    "code": f["code"],
                    "severity": f["severity"],
                    "evidence": json.loads(f["evidence_json"]),
                }
                for f in findings
            ],
            "decisions": [_decision(d).__dict__ for d in decisions],
        }

    # ------------------------------------------------------------------ decisions
    async def append_decision(
        self,
        *,
        proposal_id: str,
        verdict: Verdict,
        decided_by: DecidedBy,
        matched_rules: list[str],
        reasons: list[str],
        policy_sha256: str,
        mandate_sha256: str,
        now: datetime,
        judge: dict[str, Any] | None = None,
        token_nonce: str | None = None,
        token_expires_at: str | None = None,
        supersedes_id: str | None = None,
        decision_id: str | None = None,
    ) -> StoredDecision:
        did = decision_id or new_id("dec")
        async with self.db.transaction() as conn:
            async with conn.execute(
                "SELECT seq, row_hash FROM decision ORDER BY seq DESC LIMIT 1"
            ) as cur:
                last = await cur.fetchone()
            seq = 1 if last is None else int(last["seq"]) + 1
            prev = GENESIS_HASH if last is None else str(last["row_hash"])
            row: dict[str, Any] = {
                "id": did,
                "seq": seq,
                "proposal_id": proposal_id,
                "supersedes_id": supersedes_id,
                "verdict": verdict.value,
                "decided_by": decided_by.value,
                "matched_rules": json.dumps(matched_rules),
                "reasons_json": json.dumps(reasons),
                "policy_sha256": policy_sha256,
                "mandate_sha256": mandate_sha256,
                "judge_json": json.dumps(judge) if judge is not None else None,
                "token_nonce": token_nonce,
                "token_expires_at": token_expires_at,
                "created_at": iso(now),
                "prev_hash": prev,
            }
            row["row_hash"] = row_hash(row)
            cols = ",".join(row)
            marks = ",".join("?" for _ in row)
            await conn.execute(
                f"INSERT INTO decision({cols}) VALUES ({marks})",  # noqa: S608 - fixed column names
                tuple(row.values()),
            )
        return _decision(row)

    async def latest_decision(self, proposal_id: str) -> StoredDecision | None:
        row = await self.db.fetchone(
            "SELECT * FROM decision WHERE proposal_id=? ORDER BY seq DESC LIMIT 1", (proposal_id,)
        )
        return _decision(row) if row is not None else None

    async def get_decision(self, decision_id: str) -> StoredDecision | None:
        row = await self.db.fetchone("SELECT * FROM decision WHERE id=?", (decision_id,))
        return _decision(row) if row is not None else None

    async def list_decisions(
        self,
        *,
        verdict: str | None = None,
        since: str | None = None,
        session_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = (
            "SELECT d.*, p.session_id, p.kind FROM decision d JOIN proposal p "
            "ON p.id = d.proposal_id WHERE 1=1"
        )
        params: list[Any] = []
        if verdict:
            sql += " AND d.verdict=?"
            params.append(verdict)
        if since:
            sql += " AND d.created_at>=?"
            params.append(since)
        if session_id:
            sql += " AND p.session_id=?"
            params.append(session_id)
        sql += " ORDER BY d.seq DESC LIMIT ?"
        params.append(limit)
        rows = await self.db.fetchall(sql, params)
        return [
            _decision(r).__dict__ | {"session_id": r["session_id"], "kind": r["kind"]} for r in rows
        ]

    async def used_x402_nonces(self) -> frozenset[str]:
        rows = await self.db.fetchall(
            "SELECT a.action_json FROM action a JOIN decision d ON d.proposal_id = a.proposal_id "
            "WHERE d.verdict='allow'"
        )
        nonces = set()
        for r in rows:
            action = Action.model_validate_json(r["action_json"])
            for leaf in action.leaves():
                if leaf.nonce and leaf.kind.value == "x402":
                    nonces.add(leaf.nonce.lower())
        return frozenset(nonces)

    async def verify_chain(self) -> dict[str, Any]:
        rows = await self.db.fetchall("SELECT * FROM decision ORDER BY seq")
        prev = GENESIS_HASH
        for r in rows:
            row = dict(r)
            if row["prev_hash"] != prev or row_hash(row) != row["row_hash"]:
                return {"ok": False, "rows_checked": int(row["seq"]), "first_bad_row": row["id"]}
            prev = row["row_hash"]
        return {"ok": True, "rows_checked": len(rows), "first_bad_row": None}

    # ------------------------------------------------------------------ approvals
    async def create_approval(self, decision_id: str, now: datetime, expires_at: datetime) -> str:
        aid = new_id("apr")
        await self.db.execute(
            "INSERT INTO approval(id, decision_id, state, requested_at, expires_at)"
            " VALUES (?,?,'pending',?,?)",
            (aid, decision_id, iso(now), iso(expires_at)),
        )
        return aid

    async def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        row = await self.db.fetchone("SELECT * FROM approval WHERE id=?", (approval_id,))
        return dict(row) if row is not None else None

    async def list_approvals(self, state: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT a.*, d.proposal_id FROM approval a JOIN decision d ON d.id = a.decision_id"
        params: tuple[Any, ...] = ()
        if state:
            sql += " WHERE a.state=?"
            params = (state,)
        return [dict(r) for r in await self.db.fetchall(sql + " ORDER BY a.requested_at", params)]

    async def resolve_approval(
        self, approval_id: str, state: str, now: datetime, resolver: str, note: str | None
    ) -> bool:
        async with (
            self.db.transaction() as conn,
            conn.execute(
                "UPDATE approval SET state=?, resolved_at=?, resolver=?, note=? "
                "WHERE id=? AND state='pending' RETURNING id",
                (state, iso(now), resolver, note, approval_id),
            ) as cur,
        ):
            row = await cur.fetchone()
        return row is not None

    async def due_approvals(self, now: datetime) -> list[dict[str, Any]]:
        rows = await self.db.fetchall(
            "SELECT * FROM approval WHERE state='pending' AND expires_at<=?", (iso(now),)
        )
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ address book
    async def add_book_entry(
        self,
        label: str,
        address: str,
        chain_id: int,
        provenance: str,
        verified: bool,
        now: datetime,
    ) -> str:
        bid = new_id("abk")
        await self.db.execute(
            "INSERT INTO address_book VALUES (?,?,?,?,?,?,?)",
            (bid, label, address, chain_id, provenance, int(verified), iso(now)),
        )
        return bid

    async def book(self, chain_id: int | None = None) -> list[BookEntry]:
        sql = "SELECT * FROM address_book"
        params: tuple[Any, ...] = ()
        if chain_id is not None:
            sql += " WHERE chain_id=?"
            params = (chain_id,)
        rows = await self.db.fetchall(sql + " ORDER BY created_at", params)
        return [
            BookEntry(r["id"], r["label"], r["address"], r["provenance"], bool(r["verified"]))
            for r in rows
        ]

    async def update_book_entry(
        self, entry_id: str, *, label: str | None, verified: bool | None
    ) -> bool:
        row = await self.db.fetchone("SELECT provenance FROM address_book WHERE id=?", (entry_id,))
        if row is None:
            return False
        if label is not None:
            await self.db.execute("UPDATE address_book SET label=? WHERE id=?", (label, entry_id))
        if verified is not None:
            await self.db.execute(
                "UPDATE address_book SET verified=? WHERE id=?", (int(verified), entry_id)
            )
        return True

    async def delete_book_entry(self, entry_id: str) -> bool:
        before = await self.db.scalar("SELECT COUNT(*) FROM address_book WHERE id=?", (entry_id,))
        await self.db.execute("DELETE FROM address_book WHERE id=?", (entry_id,))
        return bool(before)
