# ADR-0006 — Static GitHub Pages demo; no hosted backend

**Status:** accepted · **Date:** 2026-09-28

## Context

The results need a public face: the frontier, the matrix, replayable episodes. A hosted backend would
put a signer or a proposal API on the internet, plus a database and an LLM quota to protect, and it
would depend on free tiers whose terms change often.

## Decision

- Publish a **static build** of the web app (`npm run build:static`) to **GitHub Pages**, reading
  committed `results/*.json`.
- Everything that decides or signs runs locally. There is no public API.

## Options considered

| Option | Why not |
|---|---|
| Render (free web service) + Neon (free Postgres) | Two free tiers chained; cold starts, sleep policies and limits change; a public endpoint invites abuse of the LLM quota and the signer |
| Cloudflare Workers | Python and long-lived SSE fit poorly; the pipeline needs anvil, which cannot run there |
| Hugging Face Spaces | Containers sleep; public by default; a poor place for a signer's secrets |
| Koyeb (free tier) | Same free-tier fragility; still exposes a signing service |
| **Static Pages + local app** | Chosen. Free, durable, nothing to attack, results readable indefinitely |

## Consequences

- The public site cannot run a live episode; the local console does, and the README shows how.
- Curated episodes are exported as JSON with the same shape as the API response.
- Free-tier churn has no effect on the published results.
