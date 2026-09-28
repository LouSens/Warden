# Product

> Status: **design**. Nothing described here is built yet. No number in this document is a
> measurement; targets are marked as targets and results do not exist until a run produces them.

## 1. What Warden is

Warden is an open-source **transaction firewall for LLM agents that hold wallets**.

It sits between an agent and the key that signs for it. Every transaction or signature the agent
proposes is:

1. **decoded** into a typed action (transfer, approve, permit, swap, delegation, x402 payment, …);
2. **simulated** on a local fork to get the exact asset and allowance changes;
3. **checked** against a catalogue of deterministic checks (lookalike recipient, unlimited approval,
   hidden delegation, honeypot token, …);
4. **judged against a mandate**: a structured, immutable statement of what the user asked for, taken
   from the user's own words before the agent reads anything else.

Anything outside the mandate is blocked or escalated to the user. Only an `allow` decision produces a
short-lived **decision token**, and a separate signer process signs only when it receives a valid
token bound to the exact transaction.

Warden ships with **WardenBench**, a deterministic benchmark: a local EVM chain, a fake world of
invoices, emails, web pages and paid APIs with injection slots, and code-based checkers that read
chain state after each episode. It measures which defence layer actually stops attacks, and what it
costs in lost utility.

## 2. The research question

> **Where should the security boundary sit for agent wallets?**
> Model-level defences (prompting, an LLM guard, plan-then-execute) versus execution-layer defences
> (deterministic policy, simulation, intent checks), compared on a deterministic benchmark with the
> same model and the same budget.

The answer is published as a utility-versus-attack-success frontier with confidence intervals, a
per-attack-class matrix, and every episode replayable in a browser.

## 3. Who it is for

| User | What they want | What Warden gives them |
|---|---|---|
| Developer of an agent that pays, swaps or signs | A guard they can drop in front of the key | Python library, REST API, MCP server; a policy file they can read |
| Security researcher | A reproducible way to compare defences | WardenBench: fixed chain, fixed tasks, code-judged outcomes, frozen hypotheses |
| Reviewer / reader of the results | To see *why* a defence worked | Static results site with episode replays and decision ledgers |

v0.1 is single-user and local. There is no hosted service.

## 4. The invariants

These six rules define the product. A change that breaks one is a bug, whatever else it improves.
[ADR-0001](decisions/0001-execution-layer-boundary.md) records why.

1. **The agent never holds a key.** A separate signer signs only a valid, unexpired `allow` decision
   token bound to the exact transaction hash.
2. **Only the user's trusted channel creates or widens a mandate.** Tool outputs, web pages,
   invoices, token metadata, memory and MCP callers never can.
3. **No LLM is on the allow path.** `allow` comes only from rules over decoded and simulated effects.
   An LLM judge can only turn `allow` into `escalate`.
4. **Default deny.**
   - Unknown calldata or typed data leads to escalate or block.
   - An escalation that times out is blocked.
   - A chain id outside the allowlist is refused by the signer.
5. **Testnets and a local chain only.** Allowed chain ids: `31337` (anvil), `84532` (Base Sepolia),
   `11155111` (Sepolia). Every other id, mainnet included, is refused, and a test asserts it.
6. **The benchmark is judged by code**, reading chain state after the episode, never by an LLM.

## 5. Questions it answers

| Question | Where the answer appears |
|---|---|
| Is this action inside what I asked for? | Verdict + mandate-satisfaction reasons on every decision |
| What exactly would it do? | Simulated asset, allowance and delegation diffs per address |
| Why was it blocked? | Findings (code, severity, evidence) and the policy rule that fired |
| Which defence should I deploy, and what does it cost? | WardenBench frontier: attack success rate next to benign utility, per defence and model |

## 6. Main use cases

- **Guard a wallet agent.** Create a mandate from a prompt ("pay Acme's invoice, at most 150 tUSD"),
  open a session, route every proposal through `POST /api/v1/proposals` or the MCP tool
  `warden_propose_transaction`, and sign only through the signer.
- **Approve escalations.** Review pending escalations in the web console with the decoded action,
  the diffs and the findings side by side; approve or deny; unanswered ones expire as blocks.
- **Tune a policy safely.** Edit `policy.yaml`, run the impact dry-run, and see every past decision
  that would change before saving.
- **Run the benchmark.** Queue a run over suites × defences × models, watch progress, then read the
  report and replay any episode.
- **Read the published results** on the static site without installing anything.

## 7. Product surfaces

| Surface | Build | Purpose |
|---|---|---|
| Python package `warden` (distribution `warden-guard`) | local | Firewall pipeline, benchmark harness, CLI `warden` |
| REST API `/api/v1` | local | Firewall, approvals, policy, address book, benchmark runs |
| Signer | local, separate process | Verifies decision tokens, signs, broadcasts |
| MCP server (stdio) | local | Lets any MCP-capable agent propose actions and read decisions |
| Web app, full build | local | Results, episode replay, live console, firewall, address book |
| Web app, static build | GitHub Pages | Results, matrix, curated episode replays, methods |

Details: [architecture.md](architecture.md), [api.md](api.md), [frontend.md](frontend.md).

## 8. Non-goals

- **Mainnet custody.** Warden refuses mainnet chain ids at the signer.
- **Trading advice or autonomous trading.** The reference agent follows explicit user tasks.
- **Being a wallet.** Warden has no key management UI, no seed backup, no balances dashboard.
- **A hosted multi-tenant service.** See [ADR-0006](decisions/0006-static-demo-no-hosted-backend.md).
- **Non-EVM chains** in v0.1.
- **Detecting bugs in legitimate protocols.** Warden checks whether an action matches the mandate
  and has no known-malicious shape; it does not audit the contracts it calls.

## 9. Honest limits (stated up front)

- The mandate is only as good as its extraction. A wrong mandate can allow a wrong action; extraction
  accuracy is measured on a 60-prompt gold set and reported.
- A human who approves every escalation turns `escalate` into `allow`. The benchmark reports attack
  success under three approver models (oracle, rubber-stamp, deny-all) to bound this.
- An allowlisted but wrong recipient (the user named the wrong address) is outside what any firewall
  can detect.
- The RPC endpoint is trusted. A malicious RPC can lie to the simulator.
- WardenBench is synthetic. Its results say which layer stops *these* attacks on *this* agent; they
  are evidence about the design question, not a guarantee for other agents.

See [threat-model.md](threat-model.md) for the full list of residual risks.

## 10. Names

| Thing | Name |
|---|---|
| Repository | `Warden` |
| Python import package | `warden` |
| Python distribution | `warden-guard` (availability on PyPI to be checked before the first publish) |
| CLI | `warden` |
| Benchmark | WardenBench |
| Reference agent | Courier |
