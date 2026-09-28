-- Signer schema. Only the signer process writes this database. See docs/data-model.md.

CREATE TABLE signature (
  id              TEXT PRIMARY KEY,
  decision_id     TEXT NOT NULL,
  token_nonce     TEXT NOT NULL UNIQUE,
  chain_id        INTEGER NOT NULL,
  payload_sha256  TEXT NOT NULL,
  tx_hash         TEXT,
  broadcast_at    TEXT,
  receipt_status  INTEGER,
  created_at      TEXT NOT NULL
);

CREATE INDEX signature_decision ON signature(decision_id);

CREATE TRIGGER signature_no_delete BEFORE DELETE ON signature
BEGIN SELECT RAISE(ABORT, 'signature log is append-only'); END;
