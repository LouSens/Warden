"""Durable job queue in SQLite: leases, exponential backoff, dead-letter, idempotency keys.

Jobs are grouped in *lanes* (one per model for benchmark episodes) so that a rate-limit pause on one
model does not stop the other. Leasing is a single ``UPDATE ... RETURNING`` inside ``BEGIN
IMMEDIATE``, so two workers cannot lease the same job.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from warden.clock import Clock, SystemClock, iso
from warden.ids import new_id
from warden.storage.database import Database


@dataclass(frozen=True)
class Job:
    id: str
    kind: str
    lane: str
    payload: dict[str, Any]
    attempts: int
    max_attempts: int
    state: str


def _row_to_job(row: Any) -> Job:
    return Job(
        id=row["id"],
        kind=row["kind"],
        lane=row["lane"],
        payload=json.loads(row["payload_json"]),
        attempts=int(row["attempts"]),
        max_attempts=int(row["max_attempts"]),
        state=row["state"],
    )


class JobQueue:
    def __init__(
        self,
        db: Database,
        clock: Clock | None = None,
        base_backoff_s: float = 10.0,
        max_backoff_s: float = 3600.0,
    ) -> None:
        self.db = db
        self.clock = clock or SystemClock()
        self.base_backoff_s = base_backoff_s
        self.max_backoff_s = max_backoff_s

    def _now(self) -> datetime:
        return self.clock.now()

    async def enqueue(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        lane: str = "default",
        idempotency_key: str | None = None,
        max_attempts: int = 3,
        delay_s: float = 0.0,
    ) -> str:
        """Add a job. With an ``idempotency_key`` already present, return the existing job id."""
        now = self._now()
        async with self.db.transaction() as conn:
            if idempotency_key is not None:
                async with conn.execute(
                    "SELECT id FROM job WHERE idempotency_key = ?", (idempotency_key,)
                ) as cur:
                    existing = await cur.fetchone()
                if existing is not None:
                    return str(existing["id"])
            job_id = new_id("job")
            await conn.execute(
                "INSERT INTO job(id, kind, lane, payload_json, idempotency_key, state, attempts,"
                " max_attempts, run_after, created_at, updated_at)"
                " VALUES (?,?,?,?,?,'queued',0,?,?,?,?)",
                (
                    job_id,
                    kind,
                    lane,
                    json.dumps(payload),
                    idempotency_key,
                    max_attempts,
                    iso(now + timedelta(seconds=delay_s)),
                    iso(now),
                    iso(now),
                ),
            )
        return job_id

    async def lease(
        self,
        *,
        lanes: list[str] | None = None,
        exclude_lanes: set[str] | None = None,
        lease_s: float = 600.0,
    ) -> Job | None:
        """Lease the oldest ready job. Expired leases become leasable again."""
        now = self._now()
        clauses = [
            "((state = 'queued' AND run_after <= :now) OR (state = 'leased' AND lease_until <= :now))"
        ]
        params: dict[str, Any] = {"now": iso(now), "until": iso(now + timedelta(seconds=lease_s))}
        if lanes:
            clauses.append("lane IN (" + ",".join(f":l{i}" for i in range(len(lanes))) + ")")
            params.update({f"l{i}": lane for i, lane in enumerate(lanes)})
        if exclude_lanes:
            ex = sorted(exclude_lanes)
            clauses.append("lane NOT IN (" + ",".join(f":x{i}" for i in range(len(ex))) + ")")
            params.update({f"x{i}": lane for i, lane in enumerate(ex)})
        where = " AND ".join(clauses)
        async with self.db.transaction() as conn:
            async with conn.execute(
                f"SELECT id FROM job WHERE {where} ORDER BY run_after, created_at LIMIT 1",  # noqa: S608 - clauses are fixed strings; values are bound
                params,
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                return None
            async with conn.execute(
                "UPDATE job SET state='leased', lease_until=:until, attempts=attempts+1,"
                " updated_at=:now WHERE id=:id RETURNING *",
                {**params, "id": row["id"]},
            ) as cur:
                leased = await cur.fetchone()
        return _row_to_job(leased) if leased is not None else None

    async def complete(self, job_id: str, result: dict[str, Any] | None = None) -> None:
        now = iso(self._now())
        await self.db.execute(
            "UPDATE job SET state='done', lease_until=NULL, result_json=?, updated_at=? WHERE id=?",
            (json.dumps(result) if result is not None else None, now, job_id),
        )

    async def fail(
        self,
        job_id: str,
        error: str,
        *,
        retry_after_s: float | None = None,
        count_attempt: bool = True,
    ) -> str:
        """Record a failure. Returns the new state: ``queued`` (will retry) or ``dead``.

        ``count_attempt=False`` is for rate-limit pauses: the job is re-queued without using up
        an attempt.
        """
        row = await self.db.fetchone("SELECT attempts, max_attempts FROM job WHERE id=?", (job_id,))
        if row is None:
            raise KeyError(job_id)
        attempts, max_attempts = int(row["attempts"]), int(row["max_attempts"])
        now = self._now()
        if not count_attempt:
            attempts -= 1
        if attempts >= max_attempts:
            state, run_after = "dead", now
        else:
            backoff = min(self.base_backoff_s * 2 ** max(attempts - 1, 0), self.max_backoff_s)
            delay = retry_after_s if retry_after_s is not None else backoff
            state, run_after = "queued", now + timedelta(seconds=delay)
        await self.db.execute(
            "UPDATE job SET state=?, attempts=?, lease_until=NULL, last_error=?, run_after=?,"
            " updated_at=? WHERE id=?",
            (state, attempts, error[:2000], iso(run_after), iso(now), job_id),
        )
        return state

    async def get(self, job_id: str) -> dict[str, Any] | None:
        row = await self.db.fetchone("SELECT * FROM job WHERE id=?", (job_id,))
        return dict(row) if row is not None else None

    async def counts(self) -> dict[str, int]:
        rows = await self.db.fetchall("SELECT state, COUNT(*) AS n FROM job GROUP BY state")
        return {str(r["state"]): int(r["n"]) for r in rows}
