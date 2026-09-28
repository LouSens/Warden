# ADR-0005 — SQLite for runtime state; files for benchmark runs

**Status:** accepted · **Date:** 2026-09-28

## Context

Runtime state (mandates, proposals, decisions, approvals, address book, jobs) belongs to one user on
one machine and must be tamper-evident. Benchmark results must be reproducible, diffable, shareable
as a tarball, and loadable by a static site. Nothing in v0.1 needs similarity search or multi-hop
graph queries.

## Decision

- **SQLite** in WAL mode through `aiosqlite` with plain SQL (no ORM), numbered SQL migrations, `VACUUM INTO`
  backup before migrating. Two files: `warden.db` (API) and `signer.db` (signer only).
- The decision log is append-only (triggers) and hash-chained.
- **Benchmark runs are files**: `manifest.json`, `episodes.jsonl`, trajectories, report. The files are
  the source of truth; curated summaries are exported to `results/`.

Details: [data-model.md](../data-model.md).

## Options considered

| Option | Why not |
|---|---|
| Postgres (local Docker or Neon) | A server for one user's rows; the app would not start without it; no needed feature is missing from SQLite |
| pgvector | No embedding or similarity query exists in the design |
| Neo4j | No multi-hop graph query exists in the design |
| An ORM (SQLAlchemy) | The schema is small and written as SQL migrations anyway; an ORM mapping would duplicate it and must be kept in sync |
| Results stored in the database | Harder to diff, archive, hash into a release or serve statically |
| **SQLite + run files** | Chosen. No services, easy backup, results that travel as files |

## Consequences

- One writer at a time. The job queue runs one episode at a time per model, which the rate limits
  require anyway.
- Hash-chain insertion must happen in one transaction (read the last hash, insert).
- A multi-user or hosted version would need a new ADR.
