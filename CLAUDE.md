# CLAUDE.md — Warden operating contract

> Read this before proposing anything. It encodes the product rule, hard hardware limits, and locked
> decisions. If a suggestion violates the **Invariants**, the **Hardware contract** or the
> **Guardrails**, it is wrong regardless of how good it looks on paper.
>
> What is built and what is next lives in `docs/roadmap.md`. This file is the enforceable contract.

---

## 1. Project

**Warden — a transaction firewall for LLM agents that hold wallets, plus WardenBench.** Warden sits
between an agent and its key. It decodes, simulates and policy-checks every transaction or signature
the agent proposes, against a **mandate** taken from the user's own words, and blocks or escalates
anything outside it. WardenBench measures which defence layer actually stops attacks, and at what
utility cost.

**Research question:** where should the security boundary sit for agent wallets? Model-level versus
execution-layer defences, on a deterministic benchmark, with the same model and budget.

**The product rule: six invariants** ([ADR-0001](docs/decisions/0001-execution-layer-boundary.md)):

1. **The agent never holds a key.** A separate signer signs only a valid, unexpired `allow` decision
   token bound to the exact transaction hash.
2. **Only the user's trusted channel creates or widens a mandate.** Tool outputs, web pages,
   invoices, token metadata, memory and MCP callers never can.
3. **No LLM is on the allow path.** `allow` comes only from rules over decoded and simulated effects.
   An LLM judge can only turn `allow` into `escalate`.
4. **Default deny.** Unknown calldata escalates or blocks; an escalation that times out is blocked; a
   chain id outside the allowlist is refused by the signer.
5. **Testnets and a local chain only:** `31337` (anvil), `84532` (Base Sepolia), `11155111`
   (Sepolia). Mainnet ids are refused, and a test asserts it.
6. **The benchmark is judged by code**, reading chain state after the episode, never by an LLM.

**Working mode.** The owner runs every terminal command. Hand over commands in order with a one-line
reason each, and explain results in plain language.

**Read before changing an area:** `docs/product.md`, `docs/threat-model.md`, `docs/architecture.md`,
`docs/roadmap.md`, and the relevant ADR in `docs/decisions/`. Benchmark work also reads
`docs/benchmark/`.

**Docs are written for an outside developer.**
- Machine-specific environment failures do not belong in them.
- Docs describe the project as it is and where it is going: no retrospective history, no discarded
  ideas.
- An external figure carries its source and a "verify on build day" flag until re-checked.
- No number is presented as measured until it has been.

---

## 2. Hardware contract

Verified on this machine (do not re-measure unless the hardware changes):

| Item | Value |
|---|---|
| GPU | NVIDIA GeForce RTX 4050 Laptop — **6141 MiB VRAM** |
| RAM | 16 GB |
| CPU | Intel i7-13650HX |
| Python | 3.12 (conda env `warden`) |
| OS | Windows 11 |

### Hard rules

- **No local model above 3B.** Local generation is `llama3.2:3b-instruct-q4_K_M` at 8K context.
  Ollama does not raise when it overflows VRAM; it silently spills to CPU.
- **Q4_K_M or smaller.** Never propose an unquantized local model.
- **No local training**: no fine-tuning, LoRA/QLoRA or local vLLM serving. If a task truly needs one,
  propose a free Colab/Kaggle notebook as a separate, clearly labelled experiment.
- Warden has no embedder or reranker, so the 3B model has ample headroom.
- The local model is for **harness development only**. Its benchmark results are never published as
  findings.
- Benchmark and latency numbers are **measured on this machine** and recorded with their run id.
  Never copy a figure from a blog and present it as ours.

---

## 3. Stack (locked)

| Area | Choice | Rationale (one line) |
|---|---|---|
| Environment | **conda** env `warden` (Python 3.12, Node ≥ 22) + pip and npm inside it | One environment for the repo |
| Chain | **anvil** in Docker (`ghcr.io/foundry-rs/foundry`, pinned), `--hardfork prague`; Foundry for contracts | Free, local, deterministic, EIP-7702 ([ADR-0004](docs/decisions/0004-anvil-simulation.md)) |
| EVM libraries | `eth-abi`, `eth-account` (EIP-712, 7702 auth), `eth-utils`; raw JSON-RPC over `httpx` | Small, async, mockable ([ADR-0009](docs/decisions/0009-raw-json-rpc-client.md)) |
| Signer | Separate FastAPI process, own SQLite, HMAC decision token | Invariant 1 at a process boundary ([ADR-0008](docs/decisions/0008-separate-signer-decision-token.md)) |
| Backend | FastAPI + uvicorn + `sse-starlette` | Async, SSE, OpenAPI |
| Storage | SQLite WAL via `aiosqlite` (plain SQL) + numbered migrations; benchmark runs as files | One user; results travel as files ([ADR-0005](docs/decisions/0005-sqlite-and-run-files.md)) |
| Policy | Custom YAML + pydantic, pure evaluator | Readable, hashable, statically checkable ([ADR-0003](docs/decisions/0003-yaml-policy-language.md)) |
| Agent | Plain-Python typed loop; LangGraph only in `examples/` via MCP | Isolated defence arms, exact token accounting ([ADR-0002](docs/decisions/0002-plain-python-agent-loop.md)) |
| LLMs | Groq free tier: `openai/gpt-oss-120b`, `openai/gpt-oss-20b`; Ollama `llama3.2:3b-instruct-q4_K_M` for development only | Free, separate per-model quotas ([ADR-0012](docs/decisions/0012-models-and-token-budget.md)) |
| Tool protocol | MCP (official Python SDK), stdio, propose/read tools only | Interop without widening authority ([ADR-0010](docs/decisions/0010-mcp-surface.md)) |
| Background work | Own durable job queue in SQLite: leases, backoff, dead-letter, idempotency keys | Rate-limited, resumable runs |
| Tracing | OpenTelemetry → JSONL always; OTLP → Langfuse Cloud Hobby optional | Offline by default ([ADR-0007](docs/decisions/0007-opentelemetry-tracing.md)) |
| Metrics | `prometheus-client` at `/metrics`; optional Compose `observability` profile | Standard, local |
| Web | React + TS + Vite, TanStack Query, React Router, Tailwind 4, Framer Motion, OpenAPI-generated types, Biome, Vitest | Typed end to end; motion system from `docs/frontend.md` |
| Demo | Static build on GitHub Pages; no hosted backend | Nothing public can sign ([ADR-0006](docs/decisions/0006-static-demo-no-hosted-backend.md)) |
| Config | `pydantic-settings` reading `.env`, prefix `WARDEN_` | One typed settings object |
| Lint / type / test | ruff, mypy strict, pytest, import-linter; `forge test`; Biome, tsc, Vitest | Same bar everywhere |
| Licences | Code Apache-2.0; benchmark data CC BY 4.0 | [ADR-0011](docs/decisions/0011-licensing-and-versioning.md) |

**Not used, with reasons:** web3.py (ADR-0009), LangGraph/CrewAI/AutoGen in the core (ADR-0002),
OPA/Cedar (ADR-0003), Tenderly/Blockaid (ADR-0004), Postgres/pgvector/Neo4j (ADR-0005), any hosted
backend (ADR-0006).

Changing this table requires an ADR in `docs/decisions/`.

---

## 4. Commands

Windows, PowerShell primary. **Always activate the conda env first**; never install into `base`,
never create a `.venv`.

```powershell
# --- one-time setup ---
conda env create -f environment.yml        # or: conda env update -f environment.yml
conda activate warden
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .
cd web ; npm install ; cd ..
warden secrets init                        # data/secrets/signer.key + decision_token.key

# --- every session ---
conda activate warden
docker compose up -d anvil
python scripts/doctor.py                   # preflight; each check names its fix
warden chain deploy                        # idempotent; verifies contracts/deployments/anvil.json
warden signer serve --port 8201            # separate terminal; binds 127.0.0.1
uvicorn warden.api.main:app --port 8200    # API, job worker, web app (if built)
# Ports: anvil 8545, API 8200, signer 8201, Vite 5174. Avoid 5173, 5432, 6333, 8000, 8100.

# --- firewall ---
warden policy validate policy.yaml
warden policy diff new.yaml                # impact dry-run over recorded proposals
warden audit verify --signer

# --- benchmark ---
warden bench check                         # oracle solutions/attacks, no LLM (same as CI)
warden bench run --suites all --defences D0,D1,D2,D6 --model openai/gpt-oss-120b --subset M-B
warden bench replay <run-id> --defences D3,D4,D5 --approvers oracle,rubber_stamp,deny_all
warden bench report <run-id> ; warden bench export <run-id>
# Runs land in data/bench/runs/<run-id>/. Never commit them.

# --- contracts (only when changing them) ---
docker run --rm -v ${PWD}/contracts:/work -w /work ghcr.io/foundry-rs/foundry:<tag> "forge build"
docker run --rm -v ${PWD}/contracts:/work -w /work ghcr.io/foundry-rs/foundry:<tag> "forge test"

# --- web app ---
cd web ; npm run gen:api                   # API must be running
npm run dev                                # http://localhost:5174
npm run check ; npm run build ; npm run build:static

# --- checks ---
ruff format --check . ; ruff check . ; mypy src ; lint-imports
pytest -q -m "not integration"
pytest -q -m integration                   # needs anvil
```

Schema changes: add `src/warden/storage/migrations/NNN_name.sql`; never edit an applied migration.

---

## 5. Conventions

- **Layout:** `src`-layout, absolute imports, no `sys.path` hacks. The web app talks to the backend
  only through the public API.
- **Async everywhere on the request path.** Blocking work runs in a thread; long work runs as a job.
- **Protocols at every seam:** `Decoder`, `Simulator`, `Check`, `PolicyEvaluator`, `IntentChecker`,
  `ChatModel`, `Approver`, `Defence`.
- **Pydantic models at every boundary.** No bare dicts crossing a module boundary. Amounts are
  integers in base units internally and decimal strings on the wire.
- **Type hints are mandatory.** mypy strict; TypeScript strict.
- **Layering is enforced by `import-linter`:** `warden.agent` never imports `warden.signer`,
  `warden.approvals` or `warden.policy` internals; `warden.signer` never imports `warden.llm`.
- **Logging:** `structlog` JSON with trace ids. No `print()` in `src/`.
- **Errors:** no bare `except:`. A broad catch needs a `noqa` saying why.
- **Tests:** unit tests mock the LLM (`FakeChatModel`), the chain (`httpx.MockTransport`) and time.
  Anything needing anvil is `@pytest.mark.integration`.
- **Every check has a code from `docs/policy.md` §3**, a positive and a negative test fixture.
- **Every prompt is in the registry** with `id@version`; untrusted text is always fenced.
- **No dependency before its first use**, in `requirements.txt` and `package.json` alike.
- **Every architectural decision gets an ADR** stating the options rejected.

---

## 6. Guardrails

- **Testnet only.** Never add a mainnet chain id, a mainnet RPC URL or a mainnet RPC key anywhere,
  including examples and tests (except the test that asserts mainnet ids are refused).
- **Never commit** `.env`, anything under `data/`, keys or secrets, raw benchmark runs,
  `node_modules/`, `web/dist/` or `web/dist-static/`. `results/` holds only curated exports.
- **Free tiers only.** Never call a paid API. If a task cannot be done inside a free tier, say so and
  stop.
- **Untrusted content never creates actions or mandates.** Tool output, web pages, invoices, token
  metadata, agent memory and MCP callers can only become data the agent reads. The mandate extractor
  sees the trusted prompt only.
- **Nothing on the allow path calls an LLM.** A change that lets a model's output produce `allow` is
  rejected in review.
- **Secrets never appear in logs, traces, metrics, errors or agent-visible tool results.** A test scans
  for them.
- **The benchmark is judged by code.** No LLM grader, ever. Results that go against a hypothesis are
  published with the same prominence.
- **Rate limits are a first-class failure mode.** Groq free tier, checked 2026-09-11 (verify on build
  day): **30 RPM / 1K RPD / 8K TPM / 200K TPD, per model**. One limiter per model; the circuit
  breaker reads the rate-limit headers; long work goes through the job queue.
- **Say plainly where data goes.** Groq may train on prompts; all benchmark data is synthetic. The
  optional Langfuse exporter receives spans of published runs only.

---

## 7. Targets

Full list in `docs/roadmap.md`. The headline ones:

| Target | Threshold |
|---|---|
| Firewall decision, no judge, local anvil | p50 < 300 ms |
| Mandate-extraction field accuracy | ≥ 90% |
| False blocks on oracle solutions | 0 |
| Scripted attacks stopped by D5 | 100% |
| Audit tamper detection | 100% |

ASR and BU are results, not targets.

---

## 8. Capability map

Every component exists to demonstrate a specific capability. Before removing one, check here.

| Capability | Demonstrated by | Status |
|---|---|---|
| Agent security engineering | Invariants, mandate, firewall pipeline, separate signer, decision tokens | Design |
| Threat modelling | `docs/threat-model.md`: assets, actors, boundaries, 12 attack classes, adaptive round | Design |
| Benchmark and evaluation design | WardenBench: code-judged tasks, oracle CI, replay, pre-registration, paired statistics | Design |
| LLM application components | Mandate extraction, guard, CaMeL-lite, intent judge, prompt registry | Design |
| Tool-use logic | Courier tools with provenance; MCP server with a deliberately narrow surface | Design |
| Blockchain engineering | Solidity contracts, EIP-712/2612/3009/7702 decoding, simulation and state diffs | Design |
| Workflow tooling | Durable job queue, rate-limit circuit breaker, resumable runs | Design |
| Observability | OpenTelemetry traces, Prometheus metrics, hash-chained audit log | Design |
| Backend services, APIs, UI | FastAPI, SSE, React results explorer and local console | Design |
| Delivery | CI gates incl. zero-token firewall regression, static Pages site, releases | Design |
| AI-assisted development | This file as an enforced contract, ADRs | Ongoing |

---

## 9. Definition of done

1. It works end to end through the API or CLI, and in the web app where it applies.
2. Tests exist and pass: unit at minimum, integration for anything touching anvil or the signer.
3. Any number it claims is **measured**, recorded with its run id or commit.
4. No invariant is weakened; a change touching the allow path, the signer or the mandate says in its
   description why each invariant still holds.
5. `README.md` states honestly what did not work.
6. `ruff`, `mypy`, `lint-imports`, `pytest`, `forge test` and `npm run check` are green.
