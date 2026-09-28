# Observability

> Status: **design**. External quotas (Langfuse) and header names (Groq) are **verify on build day**.

## 1. Goals

- Every benchmark episode and every firewall decision can be traced end to end, offline.
- Cost (tokens, requests) and latency per stage are measured, not estimated.
- Secrets never appear in traces, logs or metrics.
- The audit log can be verified at any time.

## 2. Tracing

OpenTelemetry SDK, set up in `warden.tracing` ([ADR-0007](decisions/0007-opentelemetry-tracing.md)).

**Span tree**

```
bench.episode                        attrs: case_id, defence, model, sample, approver
├─ mandate.extract                   attrs: prompt_version, cached
├─ agent.step  (×n)                  attrs: step, tool
│  ├─ llm.call                       GenAI semantic-convention attrs (below)
│  ├─ guard.check (D2)               → llm.call
│  └─ tool.call                      attrs: tool, source, trust
├─ firewall.proposal  (×m)           attrs: proposal_id, kind, origin
│  ├─ decode                         attrs: action_kind
│  ├─ simulate                       attrs: mode, reverted, gas_used
│  ├─ check.<code>  (×k)             attrs: fired, severity
│  ├─ policy                         attrs: verdict, matched_rules, policy_sha256
│  ├─ judge (D5, if called)          → llm.call
│  ├─ approval                       attrs: approver, outcome
│  └─ sign                           attrs: chain_id, ok   (never the token or signature)
├─ attacker.sweep
└─ checkers                          attrs: utility, attack_success
```

**GenAI attributes** on `llm.call`: `gen_ai.request.model`, `gen_ai.usage.input_tokens`,
`gen_ai.usage.output_tokens`, provider name, and Warden's own `warden.role`
(`agent|extractor|guard|planner|quarantine|judge|explainer`) and `warden.prompt` (`id@version`).
The GenAI semantic conventions are still marked experimental; attribute names are checked against the
current spec **on build day**.

**Prompt and completion text** is not recorded on spans by default. The benchmark's trajectories hold
the full text already; a flag (`WARDEN_TRACE_CONTENT=1`) adds it to spans for local debugging.

### 2.1 Exporters

| Exporter | When | Where |
|---|---|---|
| JSONL file | Always | `data/traces/YYYY-MM-DD.jsonl`; each episode row in `episodes.jsonl` carries its `trace_id` |
| OTLP/HTTP → Langfuse Cloud (Hobby) | Optional (`WARDEN_OTLP_ENDPOINT` set) | Published benchmark subset only |

Langfuse Hobby is free with a monthly allowance of about **50k units** (source: Langfuse pricing
page; **verify on build day**). One episode produces roughly 20–40 spans (units), so the allowance
covers about 1,250–2,500 episodes a month, enough for the published subset and not for every run.
The data is synthetic benchmark data; no personal data is sent.

## 3. Metrics

`prometheus-client`, served at `GET /metrics` on the API process.

| Metric | Type | Labels |
|---|---|---|
| `warden_decisions_total` | counter | `verdict`, `rule`, `decided_by` |
| `warden_findings_total` | counter | `code`, `severity` |
| `warden_stage_seconds` | histogram | `stage` (`decode`, `simulate`, `checks`, `policy`, `judge`, `sign`) |
| `warden_llm_tokens_total` | counter | `model`, `role`, `direction` (`in`/`out`) |
| `warden_llm_requests_total` | counter | `model`, `role`, `status` |
| `warden_ratelimit_remaining` | gauge | `model`, `kind` (`requests`, `tokens`) |
| `warden_approvals_pending` | gauge | |
| `warden_jobs` | gauge | `state` |
| `warden_signer_refusals_total` | counter | `reason` (`bad_mac`, `expired`, `reused`, `hash_mismatch`, `chain`, `ceiling`) |

Label values are bounded (codes, rules, stages, models); no addresses or ids as labels.

## 4. Logs

- `structlog`, JSON lines, with `trace_id` and `span_id` injected from the current span context.
- **Never logged:** private keys, the decision-token secret, decision tokens, signatures, signed
  payloads, API keys, full prompts (unless `WARDEN_TRACE_CONTENT=1`).
- A redaction processor drops known secret-shaped fields; a test runs a full episode with a fake
  secret, then scans all log and trace output for that secret, the token prefix `wdt1.`, and hex
  strings of private-key length, and fails if any appears.

## 5. Rate-limit circuit breaker

- The Groq provider reads the rate-limit response headers on every call
  (`x-ratelimit-remaining-requests`, `x-ratelimit-remaining-tokens`, `x-ratelimit-reset-requests`,
  `x-ratelimit-reset-tokens`, and `retry-after` on 429; names **verified on build day**).
- One limiter per model keeps a snapshot of those values and updates `warden_ratelimit_remaining`.
- When a model's remaining tokens fall below the next call's estimate, or a 429 arrives, the breaker
  **opens** for that model: the job queue stops leasing that model's episodes until the reset time,
  emits `run.paused` on the run's SSE stream, and reports `retry_after_s` in `GET /health/ready`.
- The episode in flight is retried from its start (episodes are atomic; chain state is reverted), so
  a pause loses at most one episode's tokens.

## 6. Audit

- `warden audit verify` walks the decision hash chain in `warden.db` and reports the first bad row.
- The same check is exposed as `GET /api/v1/audit:verify` and shown as a badge on the Firewall page.
- **Tests:**
  - tampering with a decision row (triggers dropped for the test) is detected: target 100% of tamper
    cases;
  - UPDATE and DELETE on `decision` raise;
  - a signature row in `signer.db` exists only for a decision id present in `warden.db` with verdict
    `allow` (cross-database consistency check, run by `warden audit verify --signer`).

## 7. What gets looked at, when

| Situation | Where |
|---|---|
| One episode behaved oddly | Episode replay page → its `trace_id` → JSONL trace |
| A benchmark run is slow or stalled | Run SSE stream (`run.paused`), `/health/ready`, `warden_jobs` |
| Firewall latency regressed | `warden_stage_seconds` p95 by stage; `firewall-regression` CI timing |
| Suspected tampering | `warden audit verify --signer` |
