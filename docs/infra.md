# Infrastructure

> Status: **design**. Image tags, faucet rules and public RPC URLs are external and change often:
> **verify on build day**.

## 1. Local environment

| Piece | How |
|---|---|
| Python 3.12, Node ≥ 22 | conda env `warden` (`environment.yml`) |
| Python packages | `pip install -r requirements.txt -r requirements-dev.txt` then `pip install -e .` inside the env |
| Web | `cd web ; npm install` |
| Chain | `docker compose up -d anvil` |
| Contracts (only to change them) | Foundry via the same Docker image; compiled output is committed |

### 1.1 Ports

| Service | Port | Bind |
|---|---|---|
| anvil | 8545 | 127.0.0.1 |
| API + worker + web (local build) | 8200 | 127.0.0.1 |
| Signer | 8201 | 127.0.0.1 only |
| Vite dev server | 5174 | 127.0.0.1 |
| Prometheus (optional profile) | 8290 | 127.0.0.1 |
| Grafana (optional profile) | 8230 | 127.0.0.1 |

Avoided because other local projects use them: 5173, 5432, 6333, 8000, 8100.

### 1.2 Every session

```powershell
conda activate warden
docker compose up -d anvil
python scripts/doctor.py                           # preflight; each failed check names its fix
warden chain deploy                                # idempotent; verifies deployments/anvil.json
warden signer serve --port 8201                    # separate terminal
uvicorn warden.api.main:app --port 8200            # API, job worker, local web build
```

First run only: `warden secrets init` creates `data/secrets/signer.key` (anvil account 1 for the
local chain) and `data/secrets/decision_token.key` (32 random bytes).

### 1.3 `scripts/doctor.py`

| Check | Fix it names |
|---|---|
| conda env active, Python 3.12 | `conda activate warden` |
| anvil reachable on :8545, chain id 31337, hardfork prague | `docker compose up -d anvil` |
| Contracts deployed at the addresses in `deployments/anvil.json` | `warden chain deploy` |
| Signer reachable on :8201 and chain allowlist correct | `warden signer serve` |
| Secrets present with restrictive permissions | `warden secrets init` |
| Groq key present and models listed | set `GROQ_API_KEY` in `.env` |
| Ollama reachable; dev model pulled; resident in VRAM at the expected size | `ollama pull llama3.2:3b-instruct-q4_K_M` |
| Ports 8200, 8201, 8545, 5174 free or owned by Warden | stop the other process |

## 2. Docker Compose

```yaml
services:
  anvil:
    image: ghcr.io/foundry-rs/foundry:<pinned tag or digest>   # verify on build day
    entrypoint: ["anvil"]
    command: ["--host", "0.0.0.0", "--port", "8545", "--chain-id", "31337",
              "--hardfork", "prague", "--timestamp", "1767225600",
              "--mnemonic", "test test test test test test test test test test test junk"]
    ports: ["127.0.0.1:8545:8545"]

  api:
    profiles: ["app"]
    build: .
    command: ["uvicorn", "warden.api.main:app", "--host", "0.0.0.0", "--port", "8200"]
    env_file: .env
    volumes: ["./data/warden:/app/data/warden", "./data/bench:/app/data/bench",
              "token-secret:/app/data/secrets:ro"]
    ports: ["127.0.0.1:8200:8200"]
    depends_on: [anvil, signer]

  signer:
    profiles: ["app"]
    build: .
    command: ["warden", "signer", "serve", "--host", "0.0.0.0", "--port", "8201"]
    volumes: ["signer-secrets:/app/data/secrets", "./data/signer:/app/data/signer"]
    # not published to the host; only the api service reaches it on the compose network

  prometheus:
    profiles: ["observability"]
    image: prom/prometheus:<pinned>
    ports: ["127.0.0.1:8290:9090"]

  grafana:
    profiles: ["observability"]
    image: grafana/grafana-oss:<pinned>
    ports: ["127.0.0.1:8230:3000"]
    volumes: ["./ops/grafana:/etc/grafana/provisioning:ro"]

volumes:
  signer-secrets: {}    # signer key + token secret
  token-secret: {}      # token secret only (populated by `warden secrets init --compose`)
```

- **Default:** `anvil` only; the API and signer run from the conda env.
- **`app` profile:** API and signer as separate containers; the signer key is in a volume the API
  container never mounts.
- **`observability` profile:** Prometheus scraping `api:8200/metrics`, Grafana with a provisioned
  dashboard (decisions by verdict, findings by code, stage latency, tokens, rate-limit headroom).

The image is CPU-only. It is built in CI and not pushed.

## 3. Contracts

```powershell
docker run --rm -v ${PWD}/contracts:/work -w /work ghcr.io/foundry-rs/foundry:<tag> "forge build"
docker run --rm -v ${PWD}/contracts:/work -w /work ghcr.io/foundry-rs/foundry:<tag> "forge test"
```

`forge build` output in `contracts/out/` is committed. CI rebuilds it and fails if the committed
bytecode differs.

## 4. Testnet mirror

`warden live --chain base-sepolia` runs about three curated episodes against a real testnet so the
results site can link to explorer transactions.

- Chains: Base Sepolia (`84532`) and Sepolia (`11155111`). Nothing else is accepted.
- RPC: a free public endpoint (`WARDEN_RPC_BASE_SEPOLIA`); no RPC key is ever committed.
- Simulation runs on a local `anvil --fork-url <rpc>`; only the final signed transaction goes to the
  public network.
- Key: a testnet-only key generated locally by `warden secrets init --testnet`; never reused on any
  other chain; the signer's allowlist still applies.
- Test funds: faucet steps are documented in the README at M6. Whether each faucet requires sign-in
  or a mainnet balance is **checked on build day**.
- The testnet contracts are the same Apache-2.0 contracts, deployed once with `warden chain deploy
  --chain base-sepolia`; their addresses go into `contracts/deployments/base-sepolia.json`.

## 5. CI (GitHub Actions)

| Job | Runs | Gate |
|---|---|---|
| `backend` | `ruff format --check`, `ruff check`, `mypy src` (strict), `lint-imports`, `pytest -m "not integration"` | all green |
| `contracts` | `forge build`, `forge test`, committed-bytecode diff | all green |
| `bench-checkers` | anvil service container; every oracle solution → `utility` true; every oracle attack → `security` true; every compatible oracle solution → `security` false. **No LLM.** | 100% of tasks |
| `firewall-regression` | Replays committed recorded proposals (`tests/golden/proposals/`) through D3, D4, D5; diffs against golden decisions | no diff unless goldens are updated in the same commit |
| `integration` | anvil service container; `pytest -m integration` (pipeline, signer, audit chain) | all green |
| `web` | `npm run check`, `npm run build`, `npm run build:static` | all green |
| `pages` | Deploys `web/dist-static/` to GitHub Pages | on tag `v*` only |
| `image` | `docker build` (not pushed) | builds |

`firewall-regression` is the benchmark's gate at zero token cost: any change to decoding, checks or
policy that alters a decision on a recorded proposal fails CI until the golden file is updated
deliberately, and the diff shows exactly which decisions moved.

## 6. Releases

- Code: `vX.Y.Z` tags; the Python distribution `warden-guard` is published to PyPI from a tag
  (name availability checked before the first publish).
- Dataset: `bench-vX.Y` tags; the dataset tarball (tasks, fixtures, templates, `contracts/out/`,
  `deployments/anvil.json`) and its SHA-256 are attached to the GitHub Release.
- Results: each published run's `results/<run-id>/` directory is committed with the release that
  produced it.

## 7. No hosted backend

There is no public API or signer. The static site is the public face; everything that can sign runs
on the user's machine. [ADR-0006](decisions/0006-static-demo-no-hosted-backend.md) gives the reasons.
