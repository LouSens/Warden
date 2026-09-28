"""Async JSON-RPC client over httpx, with typed wrappers for the methods Warden uses."""

from __future__ import annotations

import itertools
from typing import Any

import httpx


class RpcError(RuntimeError):
    def __init__(self, method: str, error: dict[str, Any]) -> None:
        self.method = method
        self.code = error.get("code")
        self.message = str(error.get("message", ""))
        self.data = error.get("data")
        super().__init__(f"{method}: {self.message} ({self.code})")


def to_hex(value: int) -> str:
    return hex(value)


def from_hex(value: str | None) -> int:
    return int(value, 16) if value else 0


class RpcClient:
    def __init__(self, url: str, client: httpx.AsyncClient | None = None, timeout_s: float = 30.0):
        self.url = url
        self._client = client or httpx.AsyncClient(timeout=timeout_s)
        self._ids = itertools.count(1)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def call(self, method: str, params: list[Any] | None = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": method,
            "params": params or [],
        }
        resp = await self._client.post(self.url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RpcError(method, data["error"])
        return data.get("result")

    # ------------------------------------------------------------------ reads
    async def chain_id(self) -> int:
        return from_hex(await self.call("eth_chainId"))

    async def block_number(self) -> int:
        return from_hex(await self.call("eth_blockNumber"))

    async def get_block(self, number: int | str = "latest") -> dict[str, Any]:
        tag = to_hex(number) if isinstance(number, int) else number
        result: dict[str, Any] = await self.call("eth_getBlockByNumber", [tag, False])
        return result

    async def balance(self, address: str, block: str = "latest") -> int:
        return from_hex(await self.call("eth_getBalance", [address, block]))

    async def code(self, address: str, block: str = "latest") -> str:
        return str(await self.call("eth_getCode", [address, block]))

    async def nonce(self, address: str, block: str = "latest") -> int:
        return from_hex(await self.call("eth_getTransactionCount", [address, block]))

    async def eth_call(
        self, to: str, data: str, sender: str | None = None, block: str = "latest"
    ) -> str:
        tx: dict[str, Any] = {"to": to, "data": data}
        if sender:
            tx["from"] = sender
        return str(await self.call("eth_call", [tx, block]))

    async def estimate_gas(self, tx: dict[str, Any]) -> int:
        return from_hex(await self.call("eth_estimateGas", [tx]))

    async def receipt(self, tx_hash: str) -> dict[str, Any] | None:
        result: dict[str, Any] | None = await self.call("eth_getTransactionReceipt", [tx_hash])
        return result

    async def transaction(self, tx_hash: str) -> dict[str, Any] | None:
        result: dict[str, Any] | None = await self.call("eth_getTransactionByHash", [tx_hash])
        return result

    async def logs(self, flt: dict[str, Any]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = await self.call("eth_getLogs", [flt])
        return result

    # ------------------------------------------------------------------ writes
    async def send_transaction(self, tx: dict[str, Any]) -> str:
        """Send from an unlocked or impersonated account (anvil)."""
        return str(await self.call("eth_sendTransaction", [tx]))

    async def send_raw(self, raw_hex: str) -> str:
        return str(await self.call("eth_sendRawTransaction", [raw_hex]))

    async def send_and_wait(self, tx: dict[str, Any]) -> dict[str, Any]:
        tx_hash = await self.send_transaction(tx)
        return await self.wait(tx_hash)

    async def wait(self, tx_hash: str) -> dict[str, Any]:
        """anvil automines, so the receipt exists as soon as the send returns."""
        rcpt = await self.receipt(tx_hash)
        if rcpt is None:
            await self.call("evm_mine")
            rcpt = await self.receipt(tx_hash)
        if rcpt is None:
            raise RpcError("wait", {"message": f"no receipt for {tx_hash}"})
        return rcpt

    # ------------------------------------------------------------------ anvil control
    async def snapshot(self) -> str:
        return str(await self.call("evm_snapshot"))

    async def revert(self, snapshot_id: str) -> bool:
        return bool(await self.call("evm_revert", [snapshot_id]))

    async def mine(self, blocks: int = 1) -> None:
        await self.call("anvil_mine", [to_hex(blocks)])

    async def impersonate(self, address: str) -> None:
        await self.call("anvil_impersonateAccount", [address])

    async def stop_impersonating(self, address: str) -> None:
        await self.call("anvil_stopImpersonatingAccount", [address])

    async def set_balance(self, address: str, wei: int) -> None:
        await self.call("anvil_setBalance", [address, to_hex(wei)])

    async def set_code(self, address: str, code: str) -> None:
        await self.call("anvil_setCode", [address, code])

    async def set_next_block_timestamp(self, ts: int) -> None:
        await self.call("evm_setNextBlockTimestamp", [ts])

    async def set_block_timestamp_interval(self, seconds: int) -> None:
        await self.call("anvil_setBlockTimestampInterval", [seconds])

    async def reset(self) -> None:
        await self.call("anvil_reset", [])
