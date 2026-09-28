from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import pytest

from warden.chain.rpc import RpcClient
from warden.chain.world import World, WorldDeployer, deployment_path, is_deployed, render_record

ANVIL_URL = "http://127.0.0.1:8545"


def _anvil_up() -> bool:
    try:
        r = httpx.post(
            ANVIL_URL, json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"}, timeout=1.0
        )
        return r.status_code == 200
    except httpx.HTTPError:
        return False


@pytest.fixture(scope="session")
def anvil_available() -> None:
    if not _anvil_up():
        pytest.skip("anvil is not running (docker compose up -d anvil)")


@pytest.fixture
async def rpc(anvil_available: None) -> AsyncIterator[RpcClient]:
    client = RpcClient(ANVIL_URL)
    yield client
    await client.aclose()


@pytest.fixture
async def world(rpc: RpcClient) -> AsyncIterator[World]:
    """A deployed world; every test runs inside its own snapshot and is reverted afterwards."""
    record = json.loads(deployment_path().read_text(encoding="utf-8"))
    if not await is_deployed(rpc, record):
        await rpc.reset()
        fresh = await WorldDeployer(rpc).deploy()
        assert render_record(fresh) == render_record(record), "deployment is not deterministic"
    snap = await rpc.snapshot()
    yield World.from_record(record)
    await rpc.revert(snap)
