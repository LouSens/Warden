# ADR-0007 — OpenTelemetry tracing with JSONL always on; Langfuse optional

**Status:** accepted · **Date:** 2026-09-28

## Context

Cost and latency per stage are headline metrics, and every episode must be debuggable offline, long
after a run. A hosted tracing UI is convenient for browsing but must not be required, and its free
quota is limited.

## Decision

- Instrument with the **OpenTelemetry** SDK, with GenAI semantic-convention attributes on LLM calls.
- A **JSONL file exporter is always on**; `episodes.jsonl` links each episode to its `trace_id`.
- An **OTLP exporter to Langfuse Cloud (Hobby)** is optional, for the published subset only.

Details: [observability.md](../observability.md).

## Options considered

| Option | Why not |
|---|---|
| Langfuse SDK only | Couples instrumentation to one vendor; nothing is recorded offline or over quota |
| Arize Phoenix | Good local UI, but another service to run; OTel output can be sent to it later with no code change |
| LangSmith | Tied to the LangChain ecosystem; account and free-tier limits |
| **OTel + JSONL + optional OTLP** | Chosen. Vendor-neutral, offline by default, any backend later |

## Consequences

- Spans must stay free of secrets; a test enforces it.
- The GenAI conventions are experimental; attribute names may change and are pinned per release.
- Langfuse usage stays inside the free allowance because only published runs are exported.
