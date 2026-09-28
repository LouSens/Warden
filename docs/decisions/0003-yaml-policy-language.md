# ADR-0003 — Custom YAML policy language with pydantic validation

**Status:** accepted · **Date:** 2026-09-28

## Context

The policy decides `allow`, `escalate` or `block` from findings, amounts and mandate satisfaction. It
must be:

- readable by a non-specialist approving a change;
- hashable, so every decision records the exact version;
- statically checkable: no `allow` without mandate satisfaction, and the default must be `block`;
- cheap to re-evaluate over thousands of recorded proposals for the impact dry-run.

## Decision

A small YAML language (`policy.yaml`), parsed into pydantic models and evaluated by a pure function
with fixed precedence `block > escalate > allow > default block`. Conditions come from a closed set
(`finding`, `finding_any`, `findings_max_severity`, `mandate_satisfied`, `amount_over`, `action`,
`chain_id`). Specification: [policy.md](../policy.md).

## Options considered

| Option | Why not |
|---|---|
| OPA / Rego | Powerful and well tested, but a second language and runtime (Go binary or WASM) for about a dozen rules; harder for a reader to verify the "no allow without mandate" property |
| Cedar | Designed for principal/action/resource authorization; the firewall's inputs (findings, diffs) fit awkwardly; adds a Rust-backed dependency |
| Python-code policies | Arbitrary code cannot be statically validated, diffed meaningfully, or safely edited from the UI |
| **Custom YAML + pydantic** | Chosen. Closed condition set, safety properties enforced by the loader, trivial dry-run |

## Consequences

- New condition types need code and a schema version bump.
- The language cannot express arbitrary logic, deliberately. Complex facts become new checks (with
  codes and tests), and rules stay simple.
- Moving to OPA later remains possible because rules are data.
