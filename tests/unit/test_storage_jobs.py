from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from warden.clock import FixedClock
from warden.jobs.queue import JobQueue
from warden.jobs.worker import Worker
from warden.llm.base import RateLimitExceeded
from warden.llm.ratelimit import LimiterRegistry
from warden.storage.database import Database
from warden.storage.migrate import MigrationError, load_migrations, migrate, split_sql


async def test_migrations_apply_once_and_are_idempotent(tmp_path: Path) -> None:
    async with Database(tmp_path / "w.db") as db:
        assert await migrate(db, "warden") == [1]
        assert await migrate(db, "warden") == []
        tables = {
            r["name"]
            for r in await db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"mandate", "proposal", "decision", "approval", "address_book", "job"} <= tables


async def test_signer_schema_is_separate(tmp_path: Path) -> None:
    async with Database(tmp_path / "s.db") as db:
        assert await migrate(db, "signer") == [1]
        tables = {
            r["name"]
            for r in await db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "signature" in tables and "decision" not in tables


async def test_edited_migration_is_refused(tmp_path: Path) -> None:
    async with Database(tmp_path / "w.db") as db:
        await migrate(db, "warden")
        await db.execute("UPDATE schema_version SET checksum='tampered' WHERE version=1")
        with pytest.raises(MigrationError, match="edited"):
            await migrate(db, "warden")


async def test_newer_database_is_refused(tmp_path: Path) -> None:
    async with Database(tmp_path / "w.db") as db:
        await migrate(db, "warden")
        await db.execute("INSERT INTO schema_version VALUES (99,'future','x','now')")
        with pytest.raises(MigrationError, match="unknown"):
            await migrate(db, "warden")


def test_split_sql_keeps_triggers_whole() -> None:
    stmts = split_sql(load_migrations(Path("src/warden/storage/migrations/warden"))[0].sql)
    triggers = [s for s in stmts if s.upper().startswith("CREATE TRIGGER")]
    assert len(triggers) == 3
    assert all(t.upper().rstrip().endswith("END") for t in triggers)


async def test_decision_log_rejects_update_and_delete(db: Database) -> None:
    await db.execute("INSERT INTO policy_version VALUES ('p','y','t')")
    await db.execute("INSERT INTO mandate VALUES ('man_1','t','t','h','{}','b','m','v')")
    await db.execute("INSERT INTO session VALUES ('ses_1','man_1','t','{}')")
    await db.execute(
        "INSERT INTO proposal VALUES ('prp_1','ses_1','tx',31337,'api','{}','h',NULL,'t')"
    )
    await db.execute(
        "INSERT INTO decision(id, seq, proposal_id, verdict, decided_by, matched_rules,"
        " reasons_json, policy_sha256, mandate_sha256, created_at, prev_hash, row_hash)"
        " VALUES ('dec_1',1,'prp_1','block','rules','[]','[]','p','b','t','0','h')"
    )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        await db.execute("UPDATE decision SET verdict='allow' WHERE id='dec_1'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        await db.execute("DELETE FROM decision WHERE id='dec_1'")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        await db.execute("UPDATE mandate SET body_json='{\"wider\":1}' WHERE id='man_1'")


async def test_agent_entries_can_never_be_verified(db: Database) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        await db.execute(
            "INSERT INTO address_book VALUES ('abk_1','Acme','0x1',31337,'agent',1,'t')"
        )


async def test_queue_lease_complete_idempotency(db: Database, clock: FixedClock) -> None:
    q = JobQueue(db, clock)
    a = await q.enqueue("bench.episode", {"n": 1}, idempotency_key="k1")
    assert await q.enqueue("bench.episode", {"n": 1}, idempotency_key="k1") == a
    job = await q.lease()
    assert job is not None and job.id == a and job.attempts == 1
    assert await q.lease() is None  # leased jobs are not handed out twice
    await q.complete(a, {"ok": True})
    assert (await q.counts()) == {"done": 1}


async def test_queue_backoff_then_dead_letter(db: Database, clock: FixedClock) -> None:
    q = JobQueue(db, clock, base_backoff_s=10)
    jid = await q.enqueue("x", {}, max_attempts=2)
    await q.lease()
    assert await q.fail(jid, "boom") == "queued"
    assert await q.lease() is None  # backing off
    clock.advance(11)
    assert (await q.lease()) is not None
    assert await q.fail(jid, "boom again") == "dead"


async def test_expired_lease_is_released(db: Database, clock: FixedClock) -> None:
    q = JobQueue(db, clock)
    await q.enqueue("x", {})
    assert await q.lease(lease_s=30) is not None
    clock.advance(31)
    assert await q.lease() is not None


async def test_worker_pauses_lane_on_rate_limit_without_using_attempt(
    db: Database, clock: FixedClock
) -> None:
    q = JobQueue(db, clock)
    limiters = LimiterRegistry()
    jid = await q.enqueue("episode", {}, lane="groq:m", max_attempts=1)

    async def handler(_job: object) -> dict[str, object]:
        limiters.get("groq:m").trip(60)
        raise RateLimitExceeded("groq:m", 60)

    worker = Worker(q, {"episode": handler}, limiters)
    assert await worker.run_once()
    row = await q.get(jid)
    assert row is not None and row["state"] == "queued" and row["attempts"] == 0
    assert await q.lease(exclude_lanes=limiters.open_models()) is None
