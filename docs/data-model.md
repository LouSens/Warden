# Data model

> Status: **design**. Runtime state lives in SQLite; benchmark results live in files. There is no
> Postgres, vector database or graph database ([ADR-0005](decisions/0005-sqlite-and-run-files.md)).

## 1. Stores

| Store | Path | Writer | Contents |
|---|---|---|---|
| `warden.db` | `data/warden.db` | API process | Mandates, sessions, proposals, decisions, approvals, address book, policies, jobs |
| `signer.db` | `data/signer/signer.db` | Signer process only | Signatures and used token nonces |
| Run files | `data/bench/runs/<run-id>/` | Benchmark runner | Manifest, episodes, trajectories, report |
| Traces | `data/traces/*.jsonl` | Both processes | OpenTelemetry spans |
| Secrets | `data/secrets/` | Setup script | `signer.key`, `decision_token.key` |
| Published results | `results/` (committed) | Export command | Curated summaries for the static site |

The signer keeps its own database so the single-use guarantee on token nonces does not depend on the
API process behaving.

Both SQLite databases use WAL mode, `foreign_keys = ON`, a 5-second busy timeout, and numbered
migrations (`storage/migrations/NNN_name.sql`) recorded in `schema_version` with a checksum. An
existing database is backed up with `VACUUM INTO` before migrating. Applied migrations are never
edited.

## 2. `warden.db` DDL

```sql
CREATE TABLE schema_version (
  version     INTEGER PRIMARY KEY,
  name        TEXT NOT NULL,
  checksum    TEXT NOT NULL,
  applied_at  TEXT NOT NULL
);

CREATE TABLE policy_version (
  sha256     TEXT PRIMARY KEY,
  yaml       TEXT NOT NULL,
  loaded_at  TEXT NOT NULL
);

CREATE TABLE mandate (
  id               TEXT PRIMARY KEY,                 -- man_…
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  prompt_sha256    TEXT NOT NULL,                    -- the prompt itself is not stored by default
  body_json        TEXT NOT NULL,                    -- canonical JSON of Mandate
  body_sha256      TEXT NOT NULL UNIQUE,
  extractor_model  TEXT,                             -- NULL for mandates:manual
  prompt_version   TEXT                              -- e.g. mandate.extract@2
);
CREATE TRIGGER mandate_immutable BEFORE UPDATE ON mandate
BEGIN SELECT RAISE(ABORT, 'mandate is immutable'); END;

CREATE TABLE session (
  id          TEXT PRIMARY KEY,                      -- ses_…
  mandate_id  TEXT NOT NULL REFERENCES mandate(id),
  created_at  TEXT NOT NULL,
  spent_json  TEXT NOT NULL DEFAULT '{}'             -- cache; recomputable from decisions
);

CREATE TABLE proposal (
  id               TEXT PRIMARY KEY,                 -- prp_…
  session_id       TEXT NOT NULL REFERENCES session(id),
  kind             TEXT NOT NULL CHECK (kind IN ('tx','typed_data','7702_auth','x402_payment')),
  chain_id         INTEGER NOT NULL,
  origin           TEXT NOT NULL CHECK (origin IN ('agent','mcp','api')),
  raw_json         TEXT NOT NULL,
  raw_sha256       TEXT NOT NULL,
  idempotency_key  TEXT UNIQUE,
  created_at       TEXT NOT NULL
);
CREATE INDEX proposal_session ON proposal(session_id, created_at);

CREATE TABLE action (
  proposal_id  TEXT PRIMARY KEY REFERENCES proposal(id),
  action_json  TEXT NOT NULL
);

CREATE TABLE simulation (
  proposal_id   TEXT PRIMARY KEY REFERENCES proposal(id),
  block_number  INTEGER NOT NULL,
  mode          TEXT NOT NULL CHECK (mode IN ('local','fork')),
  effects_json  TEXT NOT NULL,
  reverted      INTEGER NOT NULL,
  gas_used      INTEGER,
  duration_ms   INTEGER NOT NULL
);

CREATE TABLE finding (
  id             INTEGER PRIMARY KEY,
  proposal_id    TEXT NOT NULL REFERENCES proposal(id),
  code           TEXT NOT NULL,                      -- a code from policy.md §3
  severity       TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  evidence_json  TEXT NOT NULL
);
CREATE INDEX finding_code ON finding(code);

CREATE TABLE decision (
  id                TEXT PRIMARY KEY,                -- dec_…
  seq               INTEGER NOT NULL UNIQUE,         -- 1, 2, 3 … ; defines chain order
  proposal_id       TEXT NOT NULL REFERENCES proposal(id),
  supersedes_id     TEXT REFERENCES decision(id),    -- set for human and timeout decisions
  verdict           TEXT NOT NULL CHECK (verdict IN ('allow','escalate','block')),
  decided_by        TEXT NOT NULL CHECK (decided_by IN ('rules','judge','human','timeout')),
  matched_rules     TEXT NOT NULL,                   -- JSON array of rule ids
  reasons_json      TEXT NOT NULL,
  policy_sha256     TEXT NOT NULL REFERENCES policy_version(sha256),
  mandate_sha256    TEXT NOT NULL,
  judge_json        TEXT,
  token_nonce       TEXT UNIQUE,                     -- allow only
  token_expires_at  TEXT,                            -- allow only
  created_at        TEXT NOT NULL,
  prev_hash         TEXT NOT NULL,                   -- row_hash of seq-1; 64 zeros for seq = 1
  row_hash          TEXT NOT NULL
);
CREATE INDEX decision_proposal ON decision(proposal_id, seq);
CREATE TRIGGER decision_no_update BEFORE UPDATE ON decision
BEGIN SELECT RAISE(ABORT, 'decision log is append-only'); END;
CREATE TRIGGER decision_no_delete BEFORE DELETE ON decision
BEGIN SELECT RAISE(ABORT, 'decision log is append-only'); END;

CREATE TABLE approval (
  id            TEXT PRIMARY KEY,                    -- apr_…
  decision_id   TEXT NOT NULL UNIQUE REFERENCES decision(id),   -- the escalate decision
  state         TEXT NOT NULL CHECK (state IN ('pending','approved','denied','expired')),
  requested_at  TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  resolved_at   TEXT,
  resolver      TEXT,                                -- 'user' | 'timeout' | approver model name in bench
  note          TEXT
);
CREATE INDEX approval_pending ON approval(state, expires_at);

CREATE TABLE address_book (
  id          TEXT PRIMARY KEY,                      -- abk_…
  label       TEXT NOT NULL,
  address     TEXT NOT NULL,
  chain_id    INTEGER NOT NULL,
  provenance  TEXT NOT NULL CHECK (provenance IN ('user','agent','import')),
  verified    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL,
  CHECK (NOT (provenance = 'agent' AND verified = 1))
);
CREATE INDEX address_book_addr ON address_book(chain_id, address);

CREATE TABLE job (
  id               TEXT PRIMARY KEY,
  kind             TEXT NOT NULL,                    -- bench.episode, bench.replay, approvals.expire, …
  payload_json     TEXT NOT NULL,
  idempotency_key  TEXT UNIQUE,
  state            TEXT NOT NULL CHECK (state IN ('queued','leased','done','failed','dead')),
  attempts         INTEGER NOT NULL DEFAULT 0,
  max_attempts     INTEGER NOT NULL DEFAULT 3,
  run_after        TEXT NOT NULL,
  lease_until      TEXT,
  last_error       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);
CREATE INDEX job_ready ON job(state, run_after);
```

The `CHECK` on `address_book` makes "agent-written and verified" impossible at the storage layer, not
only in code.

## 3. `signer.db` DDL

```sql
CREATE TABLE signature (
  id              TEXT PRIMARY KEY,                  -- sig_…
  decision_id     TEXT NOT NULL,
  token_nonce     TEXT NOT NULL UNIQUE,              -- single use, enforced by the signer's own store
  chain_id        INTEGER NOT NULL,
  payload_sha256  TEXT NOT NULL,
  tx_hash         TEXT,                              -- NULL for typed-data signatures
  broadcast_at    TEXT,
  receipt_status  INTEGER,                           -- 1 success, 0 reverted, NULL pending / typed data
  created_at      TEXT NOT NULL
);
CREATE TRIGGER signature_no_delete BEFORE DELETE ON signature
BEGIN SELECT RAISE(ABORT, 'signature log is append-only'); END;
```

## 4. Audit chain

- `row_hash = SHA-256(prev_hash ‖ canonical_json(row without row_hash))`, hex-encoded.
- The first row's `prev_hash` is 64 zeros.
- Rows are inserted inside a transaction that reads the latest `seq` and `row_hash`, so two writers
  cannot fork the chain (SQLite allows one writer at a time).
- `warden audit verify` and `GET /api/v1/audit:verify` walk the chain in `seq` order and report the
  first row whose hash does not match. A test modifies a row with the triggers dropped and asserts
  detection.
- Session spending is recomputed from `allow` decisions (and signer receipts) when `spent_json` is
  missing or disputed; `spent_json` is a cache.

**What counts as spent.** An `allow` decision reserves its outflow against the session caps. The
reservation is released if its token expires unused (no signature with that nonce in `signer.db`).
The benchmark replay has no signer, so there every `allow` counts as spent.

## 5. Benchmark run files

Benchmark results are files and they are the source of truth. The database only holds the job that
produced them.

```
data/bench/runs/<run-id>/
  manifest.json
  episodes.jsonl
  trajectories/<eid>.json
  replays/<defence>/<eid>.json         # D3–D5 replay records
  report.md
  events.log
```

**`manifest.json`**

```json
{
  "run_id": "run_2026-10-14T09-00-00Z_7c1e",
  "created_at": "2026-10-14T09:00:00Z",
  "git": {"commit": "…", "dirty": false},
  "packages": {"warden-guard": "0.1.0", "eth-abi": "…", "httpx": "…"},
  "dataset": {"version": "bench-v0.1", "sha256": "…"},
  "preregistration_sha256": "…",
  "policy_sha256": "…",
  "contracts_bytecode_sha256": "…",
  "models": [{"id": "openai/gpt-oss-120b", "provider": "groq", "temperature": 0.7}],
  "prompts": {"agent.courier": 3, "mandate.extract": 2, "guard.detect": 1, "camel.plan": 1,
              "camel.extract": 1, "intent.judge": 1},
  "matrix": {"ladder_row": "M-B", "defences": ["D0","D1","D2","D3","D4","D5","D6"], "k": 4,
             "cases": {"benign": 20, "security": 60, "adaptive": 20}},
  "approvers": ["oracle", "rubber_stamp", "deny_all"],
  "seed": 0,
  "anvil": {"image": "ghcr.io/foundry-rs/foundry@sha256:…", "hardfork": "prague", "genesis_timestamp": 1767225600}
}
```

A run refuses to resume if any hashed input changed since it started.

**`episodes.jsonl`**: one row per episode (and per replayed defence).

| Field | Type | Meaning |
|---|---|---|
| `eid` | str | Episode id |
| `case_id` | str | `user_task` or `user_task×injection_task[slot,template]` |
| `kind` | str | `benign`, `security`, `adaptive` |
| `defence` | str | `D0`–`D6` |
| `model` | str | Model id |
| `sample` | int | 1–4 |
| `approver` | str | For D3–D5 replays |
| `mandate` | str | `extracted` or `gold` |
| `source_eid` | str | For replays, the D0 episode replayed |
| `utility` | bool | Checker result |
| `attack_success` | bool \| null | Null for benign |
| `first_block` | int \| null | Index of the first non-allowed proposal |
| `escalated` | int | Number of escalations |
| `stop_reason` | str | Agent stop reason |
| `tokens_in`, `tokens_out` | int | Agent + guard + planner + judge, split in `tokens_by_role` |
| `requests` | int | Provider requests |
| `latency_ms` | int | Wall time |
| `trace_id` | str | OpenTelemetry trace id |

**`trajectories/<eid>.json`**: messages with provenance, tool calls, proposals, decision records,
pre- and post-state, the attacker-sweep transactions, checker outputs.

**Export.** `warden bench export <run-id>` writes curated summaries to `results/`
([frontend.md §6](frontend.md#6-static-results-data)). Raw runs under `data/` are never committed.

## 6. Retention

- Runtime rows are kept indefinitely (single user; small).
- Trace JSONL files rotate daily and keep 30 days by default (`WARDEN_TRACE_RETENTION_DAYS`).
- Run directories are kept until the user deletes them.
