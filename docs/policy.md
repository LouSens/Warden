# Policy language and check catalogue

> Status: **design**. This document is the canonical list of check codes. Any other document that
> names a check must use a code from §3.

## 1. Principles

- **Rules over facts, never over prose.** A rule matches on findings, amounts, chain ids and mandate
  satisfaction, all computed by code. Rules cannot call an LLM.
- **Precedence is fixed:** `block` > `escalate` > `allow`. If no rule matches, the default verdict
  applies, and the default is `block`.
- **`allow` requires mandate satisfaction.** A rule whose `then` is `allow` is valid only if its
  `when` includes `mandate_satisfied: true`; the loader rejects any other allow rule.
- **The policy is versioned by content.** The loader computes the SHA-256 of the file bytes; every
  decision records it; `policy_version` keeps every version ever loaded.

## 2. `policy.yaml`

```yaml
version: 1

defaults:
  verdict: block                  # when no rule matches; the loader rejects anything else
  escalation_timeout_s: 600       # unanswered escalation → block
  token_ttl_s: 120                # lifetime of an allow decision token

params:
  lookalike_prefix: 4             # hex chars after 0x that must match
  lookalike_suffix: 4
  dust_threshold_usd_equiv: 0.01
  permit_max_deadline_s: 3600
  transfer_tax_max_bps: 100
  first_seen_window_blocks: 0     # 0 = entire history of the user EOA

limits:
  auto_approve_max_usd_equiv: 50  # above this, even a satisfied mandate escalates
  session_cap_from: mandate       # session caps always come from the mandate

registries:
  tokens: registries/tokens.yaml        # address, symbol, decimals, reference price
  spenders: registries/spenders.yaml    # known routers / Permit2
  services: registries/services.yaml    # x402 payees

rules:
  - id: no-delegation
    when: {finding: delegation_present}
    then: block
  - id: wrong-chain
    when: {finding: chain_mismatch}
    then: block
  - id: unlimited-approval
    when: {finding: unlimited_approval}
    then: block
  - id: lookalike
    when: {finding: lookalike_recipient}
    then: block
  - id: honeypot
    when: {finding_any: [honeypot_sell_fails, transfer_tax_over]}
    then: block
  - id: x402-abuse
    when: {finding_any: [x402_payto_mismatch, x402_nonce_reuse]}
    then: block
  - id: outside-mandate
    when: {finding_any: [recipient_not_in_mandate, action_not_in_mandate, per_tx_cap, session_cap,
                         approval_over_cap, unknown_spender, permit_spender_unknown, mandate_expired]}
    then: block
  - id: unknown
    when: {finding_any: [unknown_calldata, simulation_reverted]}
    then: escalate
  - id: new-recipient
    when: {finding_any: [first_seen_recipient, dust_origin, unverified_book_entry]}
    then: escalate
  - id: x402-price
    when: {finding: x402_price_over}
    then: escalate
  - id: over-auto-cap
    when: {amount_over: auto_approve_max_usd_equiv}
    then: escalate
  - id: mandate-ok
    when: {mandate_satisfied: true, findings_max_severity: low}
    then: allow
```

### 2.1 `when` conditions

All conditions in one `when` must hold (logical AND). Write two rules for OR, or use `finding_any`.

| Condition | Type | True when |
|---|---|---|
| `finding` | check code | A finding with this code is present |
| `finding_any` | list of check codes | Any of them is present |
| `findings_max_severity` | severity | No finding is above this severity (`info < low < medium < high < critical`) |
| `mandate_satisfied` | bool | Intent stage's rule result equals this value |
| `amount_over` | `limits` key | Total outflow at reference prices exceeds that limit |
| `action` | list of action kinds | The decoded action kind is in the list |
| `chain_id` | list of ints | The proposal's chain id is in the list |

### 2.2 Evaluation

```
matched = [r for r in rules if r.when holds]
if any(r.then == block    for r in matched): verdict = block
elif any(r.then == escalate for r in matched): verdict = escalate
elif any(r.then == allow  for r in matched): verdict = allow
else: verdict = defaults.verdict     # block
then: if verdict == allow and intent judge (D5 only) returns inconsistent|unsure: verdict = escalate
```

The decision records every matched rule id, not only the winning one.

### 2.3 Validation

`POST /api/v1/policy:validate` and `warden policy validate` reject a file that:

- is not version 1 of the schema;
- sets `defaults.verdict` to anything but `block`;
- has an `allow` rule without `mandate_satisfied: true`;
- names an unknown check code, limit, or registry path;
- has duplicate rule ids.

### 2.4 Impact dry-run

`warden policy diff new.yaml` (and `POST /api/v1/policy:dry-run`, used by the web policy editor)
re-evaluates recorded proposals with the stored actions, effects and findings under the new policy
and lists every decision whose verdict would change:

```
proposal            old       new       rule (new)
prp_01J9…Q2         allow     escalate  over-auto-cap
prp_01J9…W7         escalate  block     new-recipient → outside-mandate
2 of 418 decisions would change (0 allow → block, 1 allow → escalate, 1 escalate → block)
```

Checks whose parameters changed are re-run on the stored action and effects (no new simulation).
`PUT /api/v1/policy` refuses to save while the dry-run has not been requested for that exact file hash.

## 3. Check catalogue

Every check has a code, inputs, a default severity, the defence group it belongs to
([spec.md §6](benchmark/spec.md#6-defence-configurations)) and a unit test with one positive and one
negative fixture. **25 checks.**

| Code | Group | Inputs | Fires when | Severity |
|---|---|---|---|---|
| `chain_mismatch` | decoded | proposal, mandate | Proposal chain id ∉ mandate chain ids | critical |
| `mandate_expired` | decoded | mandate, clock | Mandate or session past `expires_at` | high |
| `action_not_in_mandate` | decoded | action, mandate | Action kind ∉ `allowed_actions` | high |
| `recipient_not_in_mandate` | decoded | action, mandate | A transfer, x402 or permit-transfer destination ∉ mandate recipients | high |
| `unverified_book_entry` | decoded | action, address book | Destination matches an address-book entry with `provenance = agent` or `verified = false` | medium |
| `per_tx_cap` | decoded | action (D3) or effects (D4+), mandate | Outflow of an asset in this proposal > per-tx cap | high |
| `session_cap` | decoded | as above + session | Session spent + this outflow > session cap | high |
| `unlimited_approval` | decoded | action | Approval, permit or Permit2 amount ≥ 2^255, or `set_approval_for_all(true)` | critical |
| `unknown_spender` | decoded | action, mandate, spender registry | Approval spender ∉ mandate spenders | high |
| `approval_over_cap` | decoded | action, mandate | Approval amount > mandate approval cap for that spender and asset | high |
| `permit_spender_unknown` | decoded | typed data, mandate | EIP-2612 / Permit2 spender ∉ mandate spenders | high |
| `permit_deadline_too_long` | decoded | typed data, clock, params | Permit deadline or expiration > now + `permit_max_deadline_s` | medium |
| `delegation_present` | decoded | action (incl. type-4 `authorization_list`) | Any EIP-7702 authorization, anywhere in the proposal | critical |
| `token_not_in_registry` | decoded | action, token registry | A token touched by the action is not in the registry | medium |
| `x402_price_over` | decoded | x402 requirements, mandate | Price > mandate per-request cap for that service | medium |
| `x402_payto_mismatch` | decoded | x402 requirements, service registry, mandate | `payTo` ≠ registered payee of the mandate's service | critical |
| `x402_nonce_reuse` | decoded | EIP-3009 nonce, decision history | Nonce already used in an allowed decision | critical |
| `unknown_calldata` | decoded | action | Calldata, typed data or selector not decodable | medium |
| `unexpected_outflow` | simulation | effects, action | Simulated outflow of any asset not declared by the decoded action (hidden transfer, fee, sweep) | high |
| `honeypot_sell_fails` | simulation | effects of simulated sell | Selling the bought amount reverts | critical |
| `transfer_tax_over` | simulation | effects | Received / sent ratio implies tax > `transfer_tax_max_bps` | high |
| `simulation_reverted` | simulation | effects | The proposal itself reverts in simulation | low |
| `lookalike_recipient` | history | action, address book, own-tx history, mandate recipients | Destination shares ≥ `lookalike_prefix` leading and ≥ `lookalike_suffix` trailing hex chars (case-insensitive) with a known counterparty but is not equal to it | critical |
| `dust_origin` | history | own-tx history, transfer logs | Destination appears in the user's history only through zero-value or sub-`dust_threshold_usd_equiv` transfers | high |
| `first_seen_recipient` | history | own-tx history | The user EOA never sent a transaction to this destination | low |

**Known counterparties** for `lookalike_recipient` are: mandate recipients, verified address-book
entries, and destinations of transactions the user EOA itself signed (`tx.from == user`). Transfer
logs alone never make an address a known counterparty, because zero-value `transferFrom` calls can
forge them. That is the address-poisoning mechanism.

**Evidence** is a small JSON object per finding, rendered in the UI. For example:

```json
{"code": "lookalike_recipient", "severity": "critical",
 "evidence": {"destination": "0x3C44e0B1d7a5F4c2918b3E6f0D2a7C51b9e093BC",
              "imitates": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
              "imitates_label": "Acme Corp (book, verified)",
              "prefix_match": 4, "suffix_match": 4}}
```

## 4. Mandate fields used by the policy

The mandate schema is defined in [agents.md §2](agents.md#2-mandate-extractor). The policy and checks
read: `chain_ids`, `recipients`, `assets`, `per_tx_cap`, `session_cap`, `allowed_actions`,
`spenders`, `approval_caps`, `services`, `delegation` (always `forbidden` in v0.1), `expires_at`,
`constraints` (free text, judge only) and `unresolved`.

Any action that touches a phrase in `unresolved` (for example, "the usual vendor") cannot satisfy the
mandate, so it can never reach `allow`: with no other finding it falls to the default `block`.
