# ADR-0004 — Simulation by anvil snapshot/revert and fork mode

**Status:** accepted · **Date:** 2026-09-28

## Context

Decoding shows what a transaction *says*; simulation shows what it *does*: hidden transfers, transfer
taxes, sells that revert, allowance changes inside a router call. The simulator must be free, work
offline, be deterministic for the benchmark, support EIP-7702, and behave the same on the local
chain and on testnets.

## Decision

- Simulate by `evm_snapshot` → impersonate the sender → execute → read state and logs → `evm_revert`,
  on **anvil** (`--hardfork prague`).
- On testnets, simulate on a local `anvil --fork-url <rpc>`, never on the public node.
- The honeypot and transfer-tax tests run a follow-up sell inside the same snapshot.

## Options considered

| Option | Why not |
|---|---|
| RPC `eth_call` with state overrides only | No multi-transaction sequences (buy then sell); logs for token diffs are not available from every node; 7702 support varies by client |
| Tenderly simulation API | Needs an account and API key, paid tiers for volume, and the network; the benchmark could not run offline |
| Blockaid (or a similar transaction-scanning API) | Commercial service; results are neither reproducible nor inspectable, and it would replace the thing being measured |
| **anvil snapshot/revert + fork mode** | Chosen. Free, local, deterministic, full EVM semantics, one code path for local and fork |

## Consequences

- anvil (in Docker) is a runtime dependency; `doctor.py` checks it.
- Fork mode trusts the RPC it forks from, as the threat model states.
- Simulation latency is dominated by RPC round trips; the p50 target (below 300 ms without the judge)
  is measured, not assumed.
