"""REST API end to end: manual mandate → session → proposals → approvals → signing → audit."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from warden.api.main import create_app
from warden.chain.abi import load_artifact
from warden.chain.world import World, units
from warden.config import Settings
from warden.secrets import init_secrets
from warden.signer.app import create_signer_app

pytestmark = pytest.mark.integration
TOKEN = load_artifact("AuthToken")
LOOKALIKE = "0x3C44e0B1d7a5F4c2918b3E6f0D2a7C51b9e093BC"


@pytest.fixture
def clients(world: World, tmp_path: Path) -> Iterator[tuple[TestClient, TestClient]]:
    settings = Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        groq_api_key=None,  # type: ignore[call-arg]
        llm_cache=False,
    )
    init_secrets(settings.secrets_dir)
    with (
        TestClient(create_app(settings, run_worker=False)) as api,
        TestClient(create_signer_app(settings)) as signer,
    ):
        yield api, signer


def _proposal(world: World, to: str, whole: int) -> dict[str, Any]:
    usd = world.token("tUSD")
    return {
        "chain_id": 31337,
        "from": world.user,
        "to": usd.address,
        "value": "0",
        "data": TOKEN.encode_call("transfer", to, units(whole, 6)),
    }


def test_api_flow(clients: tuple[TestClient, TestClient], world: World) -> None:
    api, signer = clients
    assert api.get("/health/ready").json()["firewall"] is True
    usd = world.token("tUSD").address
    acme = world.accounts["acme"]

    book = api.post("/api/v1/address-book", json={"label": "Acme Corp", "address": acme}).json()
    assert book["verified"] is True
    mandate = {
        "chain_ids": [31337],
        "recipients": [{"label": "Acme Corp", "address": acme, "source": "book"}],
        "assets": [usd],
        "per_tx_cap": {usd: str(units(150, 6))},
        "session_cap": {usd: str(units(300, 6))},
        "allowed_actions": ["transfer"],
        "expires_at": "2099-01-01T00:00:00Z",
    }
    m = api.post("/api/v1/mandates:manual", json=mandate)
    assert m.status_code == 200, m.text
    sid = api.post("/api/v1/sessions", json={"mandate_id": m.json()["id"]}).json()["id"]

    ok = api.post(
        "/api/v1/proposals",
        headers={"Idempotency-Key": "k-1"},
        json={"session_id": sid, "kind": "tx", "payload": _proposal(world, acme, 120)},
    ).json()
    assert ok["verdict"] == "allow" and ok["decision_token"].startswith("wdt1.")
    again = api.post(
        "/api/v1/proposals",
        headers={"Idempotency-Key": "k-1"},
        json={"session_id": sid, "kind": "tx", "payload": _proposal(world, acme, 120)},
    ).json()
    assert again["proposal_id"] == ok["proposal_id"] and again["decision_token"] is None
    conflict = api.post(
        "/api/v1/proposals",
        headers={"Idempotency-Key": "k-1"},
        json={"session_id": sid, "kind": "tx", "payload": _proposal(world, acme, 121)},
    )
    assert conflict.status_code == 409

    # Sign through the signer app directly (the API's /sign forwards to it over HTTP).
    record = api.get(f"/api/v1/proposals/{ok['proposal_id']}").json()
    signed = signer.post(
        "/sign",
        json={"decision_token": ok["decision_token"], "proposal": record["proposal"]["raw"]},
    )
    assert signed.status_code == 200 and signed.json()["receipt_status"] == 1
    reused = signer.post(
        "/sign",
        json={"decision_token": ok["decision_token"], "proposal": record["proposal"]["raw"]},
    )
    assert reused.status_code == 403 and reused.json()["reason"] == "reused"

    blocked = api.post(
        "/api/v1/proposals",
        json={"session_id": sid, "kind": "tx", "payload": _proposal(world, LOOKALIKE, 120)},
    ).json()
    assert blocked["verdict"] == "block" and blocked["decision_token"] is None
    assert "lookalike_recipient" in {f["code"] for f in blocked["findings"]}

    unknown = {**_proposal(world, acme, 1), "data": "0xdeadbeef"}
    esc = api.post(
        "/api/v1/proposals", json={"session_id": sid, "kind": "tx", "payload": unknown}
    ).json()
    assert esc["verdict"] == "escalate"
    pending = api.get("/api/v1/approvals?state=pending").json()
    assert [a["id"] for a in pending] == [esc["approval_id"]]
    denied = api.post(f"/api/v1/approvals/{esc['approval_id']}:deny", json={"note": "no"})
    assert denied.json()["verdict"] == "block"
    assert api.post(f"/api/v1/approvals/{esc['approval_id']}:approve").status_code == 409

    session = api.get(f"/api/v1/sessions/{sid}").json()
    assert session["caps"][0]["spent"] == str(units(120, 6))
    assert api.get("/api/v1/audit:verify").json()["ok"] is True
    assert len(api.get("/api/v1/decisions").json()) >= 4

    mainnet = api.post(
        "/api/v1/proposals",
        json={
            "session_id": sid,
            "kind": "tx",
            "payload": {**_proposal(world, acme, 1), "chain_id": 1},
        },
    )
    assert mainnet.status_code == 400 and mainnet.json()["error"] == "unsupported_chain"


def test_policy_endpoints(clients: tuple[TestClient, TestClient]) -> None:
    api, _ = clients
    current = api.get("/api/v1/policy").json()
    assert api.post("/api/v1/policy:validate", json={"yaml": current["yaml"]}).json()["valid"]
    bad = api.post(
        "/api/v1/policy:validate",
        json={"yaml": "version: 1\nrules: [{id: a, when: {}, then: allow}]"},
    ).json()
    assert bad["valid"] is False
    stricter = current["yaml"].replace(
        "auto_approve_max_usd_equiv: 1000", "auto_approve_max_usd_equiv: 10"
    )
    assert api.put("/api/v1/policy", json={"yaml": stricter}).status_code == 428
    report = api.post("/api/v1/policy:dry-run", json={"yaml": stricter}).json()
    assert "changed" in report
