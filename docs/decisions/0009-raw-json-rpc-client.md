# ADR-0009 — Raw JSON-RPC over httpx with eth-abi and eth-account

**Status:** accepted · **Date:** 2026-09-28

## Context

Warden needs a small, async, well-typed set of chain operations: state reads, `eth_call`, sending raw
transactions, anvil control methods (`evm_snapshot`, `evm_revert`, `anvil_impersonateAccount`, …),
ABI and EIP-712 encoding, and signing, including EIP-7702 authorizations. All of it must be easy to
mock in tests.

## Decision

- JSON-RPC over **`httpx`** (async) in `warden.chain`, with typed wrappers for the methods used.
- **`eth-abi`** for encoding and decoding, **`eth-account`** for signing (transactions, EIP-712 typed
  data, 7702 authorizations), **`eth-utils`** for checksums and hashing.
- Tests mock the transport with `httpx.MockTransport`.

## Options considered

| Option | Why not |
|---|---|
| web3.py | A large surface and middleware stack for a few dozen calls; anvil-specific methods still need raw calls; its async API has historically trailed the sync one |
| viem (TypeScript backend) | An excellent library, but it would split the backend across two languages; the benchmark, statistics and LLM code are Python |
| **httpx + eth-abi + eth-account** | Chosen. Minimal, async, fully mockable, and the same libraries web3.py builds on |

## Consequences

- Warden owns a thin RPC client and its error mapping.
- EIP-7702 authorization signing depends on the `eth-account` version; the minimum version is pinned
  and checked on build day.
