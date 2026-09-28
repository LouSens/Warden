"""The user EOA's history, split into trusted and forgeable parts.

* ``own_destinations``: destinations of transactions the user itself signed (``tx.from == user``):
  native value recipients and ERC-20 ``transfer`` recipients decoded from the calldata.
* ``log_only``: addresses that appear as recipients in ``Transfer(from=user, ...)`` logs but were
  never paid by a user-signed transaction. Zero-value ``transferFrom`` calls forge exactly these
  entries (address poisoning), so they are never treated as known counterparties.
"""

from __future__ import annotations

from warden.chain.abi import TRANSFER_TOPIC, checksum, selector_of, topic_to_address
from warden.chain.registry import Registries
from warden.chain.rpc import RpcClient
from warden.checks.context import HistoryView

_TRANSFER_SEL = selector_of("transfer(address,uint256)")[2:]


class HistoryIndex:
    """Incrementally scans blocks. Cheap on anvil (hundreds of blocks); cached between calls."""

    def __init__(self, rpc: RpcClient, user: str, registries: Registries) -> None:
        self.rpc = rpc
        self.user = checksum(user)
        self.registries = registries
        self._next_block = 0
        self._own: set[str] = set()
        self._log: dict[str, float | None] = {}

    def reset(self) -> None:
        self._next_block = 0
        self._own.clear()
        self._log.clear()

    async def refresh(self) -> HistoryView:
        latest = await self.rpc.block_number()
        if latest < self._next_block - 1:  # chain was reverted below what we scanned
            self.reset()
        user = self.user.lower()
        for n in range(self._next_block, latest + 1):
            block = await self.rpc.call("eth_getBlockByNumber", [hex(n), True])
            for tx in block.get("transactions", []):
                if str(tx.get("from", "")).lower() != user:
                    continue
                to = tx.get("to")
                data = str(tx.get("input", "0x"))[2:]
                if to and int(tx.get("value", "0x0"), 16) > 0:
                    self._own.add(to.lower())
                if to and data.startswith(_TRANSFER_SEL) and len(data) >= 8 + 64:
                    self._own.add(("0x" + data[8 + 24 : 8 + 64]).lower())
        if latest >= self._next_block:
            user_topic = "0x" + "0" * 24 + user[2:]
            logs = await self.rpc.logs(
                {
                    "fromBlock": hex(self._next_block),
                    "toBlock": hex(latest),
                    "topics": [TRANSFER_TOPIC, user_topic],
                }
            )
            for log in logs:
                dest = topic_to_address(log["topics"][2]).lower()
                amount = int(log.get("data", "0x0") or "0x0", 16)
                value = self.registries.usd_value(log["address"], amount)
                usd = float(value) if value is not None else None
                prev = self._log.get(dest, 0.0)
                if dest not in self._log:
                    self._log[dest] = usd
                elif usd is None or prev is None:
                    self._log[dest] = (
                        None
                        if (usd is None and prev is None)
                        else max(x for x in (usd, prev) if x is not None)
                    )
                else:
                    self._log[dest] = max(prev, usd)
            self._next_block = latest + 1
        log_only = {a: v for a, v in self._log.items() if a not in self._own}
        return HistoryView(frozenset(self._own), log_only)
