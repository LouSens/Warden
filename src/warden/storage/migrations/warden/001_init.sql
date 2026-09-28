-- Warden runtime schema. See docs/data-model.md.

CREATE TABLE policy_version (
  sha256     TEXT PRIMARY KEY,
  yaml       TEXT NOT NULL,
  loaded_at  TEXT NOT NULL
);

CREATE TABLE mandate (
  id               TEXT PRIMARY KEY,
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  prompt_sha256    TEXT NOT NULL,
  body_json        TEXT NOT NULL,
  body_sha256      TEXT NOT NULL UNIQUE,
  extractor_model  TEXT,
  prompt_version   TEXT
);

CREATE TRIGGER mandate_immutable BEFORE UPDATE ON mandate
BEGIN SELECT RAISE(ABORT, 'mandate is immutable'); END;

CREATE TABLE session (
  id          TEXT PRIMARY KEY,
  mandate_id  TEXT NOT NULL REFERENCES mandate(id),
  created_at  TEXT NOT NULL,
  spent_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE proposal (
  id               TEXT PRIMARY KEY,
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
  mode          TEXT NOT NULL CHECK (mode IN ('local','fork','declared')),
  effects_json  TEXT NOT NULL,
  reverted      INTEGER NOT NULL,
  gas_used      INTEGER,
  duration_ms   INTEGER NOT NULL
);

CREATE TABLE finding (
  id             INTEGER PRIMARY KEY,
  proposal_id    TEXT NOT NULL REFERENCES proposal(id),
  code           TEXT NOT NULL,
  severity       TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  evidence_json  TEXT NOT NULL
);

CREATE INDEX finding_code ON finding(code);

CREATE TABLE decision (
  id                TEXT PRIMARY KEY,
  seq               INTEGER NOT NULL UNIQUE,
  proposal_id       TEXT NOT NULL REFERENCES proposal(id),
  supersedes_id     TEXT REFERENCES decision(id),
  verdict           TEXT NOT NULL CHECK (verdict IN ('allow','escalate','block')),
  decided_by        TEXT NOT NULL CHECK (decided_by IN ('rules','judge','human','timeout')),
  matched_rules     TEXT NOT NULL,
  reasons_json      TEXT NOT NULL,
  policy_sha256     TEXT NOT NULL REFERENCES policy_version(sha256),
  mandate_sha256    TEXT NOT NULL,
  judge_json        TEXT,
  token_nonce       TEXT UNIQUE,
  token_expires_at  TEXT,
  created_at        TEXT NOT NULL,
  prev_hash         TEXT NOT NULL,
  row_hash          TEXT NOT NULL
);

CREATE INDEX decision_proposal ON decision(proposal_id, seq);

CREATE TRIGGER decision_no_update BEFORE UPDATE ON decision
BEGIN SELECT RAISE(ABORT, 'decision log is append-only'); END;

CREATE TRIGGER decision_no_delete BEFORE DELETE ON decision
BEGIN SELECT RAISE(ABORT, 'decision log is append-only'); END;

CREATE TABLE approval (
  id            TEXT PRIMARY KEY,
  decision_id   TEXT NOT NULL UNIQUE REFERENCES decision(id),
  state         TEXT NOT NULL CHECK (state IN ('pending','approved','denied','expired')),
  requested_at  TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  resolved_at   TEXT,
  resolver      TEXT,
  note          TEXT
);

CREATE INDEX approval_pending ON approval(state, expires_at);

CREATE TABLE address_book (
  id          TEXT PRIMARY KEY,
  label       TEXT NOT NULL,
  address     TEXT NOT NULL,
  chain_id    INTEGER NOT NULL,
  provenance  TEXT NOT NULL CHECK (provenance IN ('user','agent','import')),
  verified    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL,
  CHECK (NOT (provenance = 'agent' AND verified = 1))
);

CREATE INDEX address_book_addr ON address_book(chain_id, address);

CREATE TABLE idempotency (
  key           TEXT PRIMARY KEY,
  method        TEXT NOT NULL,
  path          TEXT NOT NULL,
  body_sha256   TEXT NOT NULL,
  status        INTEGER NOT NULL,
  response_json TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE job (
  id               TEXT PRIMARY KEY,
  kind             TEXT NOT NULL,
  lane             TEXT NOT NULL DEFAULT 'default',
  payload_json     TEXT NOT NULL,
  idempotency_key  TEXT UNIQUE,
  state            TEXT NOT NULL CHECK (state IN ('queued','leased','done','failed','dead')),
  attempts         INTEGER NOT NULL DEFAULT 0,
  max_attempts     INTEGER NOT NULL DEFAULT 3,
  run_after        TEXT NOT NULL,
  lease_until      TEXT,
  last_error       TEXT,
  result_json      TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX job_ready ON job(state, lane, run_after);
