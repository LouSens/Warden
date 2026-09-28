from __future__ import annotations

import json
from pathlib import Path

import pytest
import structlog
from fastapi.testclient import TestClient

from warden.api.main import create_app
from warden.config import Settings
from warden.logging import configure_logging
from warden.secrets import init_secrets, read_token_secret
from warden.tracing import JsonlSpanExporter


def test_health_and_request_id(settings: Settings) -> None:
    with TestClient(create_app(settings, run_worker=False)) as client:
        r = client.get("/health")
        assert r.status_code == 200 and r.json() == {"status": "ok"}
        assert r.headers["X-Request-ID"].startswith("req_")
        ready = client.get("/health/ready").json()
        assert ready["anvil"] in (True, False) and "queue" in ready


def test_secrets_init(tmp_path: Path) -> None:
    written = init_secrets(tmp_path)
    assert len(written) == 2
    assert len(read_token_secret(tmp_path)) == 32
    assert init_secrets(tmp_path) == []


def test_logs_never_contain_secrets(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", json=True)
    log = structlog.get_logger("t")
    secret = "ab" * 32
    log.info(
        "sign",
        decision_token="wdt1.eyJhIjoxfQ.c2ln",
        private_key=secret,
        note=f"key is {secret}",
        api_key="gsk_" + "x" * 30,
        proposal_sha256="cd" * 32,
    )
    err = capsys.readouterr().err
    assert secret not in err and "wdt1." not in err and "gsk_" not in err
    assert "cd" * 32 in err  # hashes are allowed through
    json.loads(err.strip().splitlines()[-1])


def test_jsonl_exporter_writes_spans(tmp_path: Path) -> None:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(tmp_path)))
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("firewall.proposal") as span:
        span.set_attribute("proposal_id", "prp_1")
        with tracer.start_as_current_span("decode"):
            pass
    lines = [
        json.loads(line) for f in tmp_path.glob("*.jsonl") for line in f.read_text().splitlines()
    ]
    names = {s["name"] for s in lines}
    assert names == {"firewall.proposal", "decode"}
    child = next(s for s in lines if s["name"] == "decode")
    parent = next(s for s in lines if s["name"] == "firewall.proposal")
    assert child["parent_span_id"] == parent["span_id"] and child["trace_id"] == parent["trace_id"]
