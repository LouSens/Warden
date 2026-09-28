"""Preflight checks. Each failed check names its fix."""

from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx

from warden.config import Settings
from warden.secrets import SIGNER_KEY_FILE, TOKEN_KEY_FILE


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""
    required: bool = True


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _rpc(url: str, method: str, params: list[object] | None = None) -> object:
    r = httpx.post(
        url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}, timeout=3.0
    )
    r.raise_for_status()
    return r.json().get("result")


def run_checks(settings: Settings) -> list[Check]:
    out: list[Check] = []
    py_ok = sys.version_info[:2] == (3, 12)
    out.append(Check("python 3.12", py_ok, sys.version.split()[0], "conda activate warden"))
    env = os.environ.get("CONDA_DEFAULT_ENV", "")
    out.append(
        Check(
            "conda env 'warden' active",
            env == "warden",
            env or "(none)",
            "conda activate warden",
            required=False,
        )
    )

    try:
        chain_id = int(str(_rpc(settings.rpc_url, "eth_chainId")), 16)
        out.append(Check("anvil reachable", True, f"{settings.rpc_url} chain {chain_id}"))
        out.append(
            Check(
                "chain id matches settings",
                chain_id == settings.chain_id,
                f"{chain_id} vs {settings.chain_id}",
                "check WARDEN_CHAIN_ID / WARDEN_RPC_URL",
            )
        )
    except (httpx.HTTPError, ValueError) as exc:
        out.append(
            Check("anvil reachable", False, type(exc).__name__, "docker compose up -d anvil")
        )

    deployments = Path("contracts/deployments/anvil.json")
    out.append(
        Check(
            "contract deployment record",
            deployments.exists(),
            str(deployments),
            "warden chain deploy",
            required=False,
        )
    )

    try:
        r = httpx.get(f"{settings.signer_url}/health", timeout=2.0)
        out.append(
            Check(
                "signer reachable",
                r.status_code == 200,
                settings.signer_url,
                "warden signer serve",
                required=False,
            )
        )
    except httpx.HTTPError:
        out.append(
            Check(
                "signer reachable",
                False,
                settings.signer_url,
                "warden signer serve",
                required=False,
            )
        )

    for name in (SIGNER_KEY_FILE, TOKEN_KEY_FILE):
        p = settings.secrets_dir / name
        out.append(Check(f"secret {name}", p.exists(), str(p), "warden secrets init"))

    out.append(
        Check(
            "GROQ_API_KEY set",
            settings.groq_api_key is not None,
            "set" if settings.groq_api_key else "missing",
            "add GROQ_API_KEY=... to .env (free key at console.groq.com)",
            required=False,
        )
    )

    try:
        r = httpx.get(settings.ollama_base_url.removesuffix("/v1") + "/api/tags", timeout=2.0)
        names = [m.get("name", "") for m in r.json().get("models", [])]
        has = any(n.startswith("llama3.2:3b-instruct-q4_K_M") for n in names)
        out.append(
            Check(
                "ollama dev model",
                has,
                ", ".join(names) or "(none)",
                "ollama pull llama3.2:3b-instruct-q4_K_M",
                required=False,
            )
        )
    except (httpx.HTTPError, ValueError):
        out.append(
            Check(
                "ollama reachable", False, settings.ollama_base_url, "start Ollama", required=False
            )
        )

    for port, owner in (
        (settings.api_port, "API"),
        (settings.signer_port, "signer"),
        (5174, "Vite"),
    ):
        used = _port_in_use(port)
        out.append(
            Check(
                f"port {port} ({owner})",
                True,
                "in use (fine if it is Warden)" if used else "free",
                required=False,
            )
        )
    return out
