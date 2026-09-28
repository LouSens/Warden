"""Simulation by snapshot → impersonate → execute → read → revert (ADR-0004).

Transactions are executed for real inside an anvil snapshot, with a zero base fee and gas price so
native balance changes are exactly the value moved. Token changes come from ``Transfer`` logs (which
makes transfer taxes visible), allowance changes from ``Approval`` logs with the before-value read
at the previous block. EIP-7702 authorizations are emulated by writing the delegation designator
(``0xef0100 || delegate``) to the sender's code inside the snapshot.

Typed data, x402 payments and bare 7702 authorizations are not transactions; their effects are
*declared* from the decoded action (mode ``declared``).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Protocol

from warden.chain.abi import APPROVAL_TOPIC, TRANSFER_TOPIC, load_artifact, topic_to_address
from warden.chain.rpc import RpcClient, RpcError, from_hex
from warden.firewall.models import (
    NATIVE,
    Action,
    ActionKind,
    AllowanceDelta,
    AssetDelta,
    DelegationDelta,
    Effects,
    Proposal,
    ProposalKind,
)

_ERC20 = load_artifact("TestToken")
_AMM = load_artifact("MiniAMM")


class Simulator(Protocol):
    async def simulate(self, proposal: Proposal, action: Action) -> Effects: ...


def declared_effects(action: Action) -> Effects:
    """Effects a non-transaction proposal declares (typed data, x402, 7702 authorization)."""
    fx = Effects(mode="declared")
    for leaf in action.leaves():
        if leaf.kind in (ActionKind.TRANSFER, ActionKind.X402) and leaf.owner and leaf.to:
            amt = leaf.amount or 0
            fx.assets.append(AssetDelta(address=leaf.owner, token=leaf.token or NATIVE, delta=-amt))
            fx.assets.append(AssetDelta(address=leaf.to, token=leaf.token or NATIVE, delta=amt))
        elif leaf.kind in (ActionKind.PERMIT, ActionKind.PERMIT2) and leaf.owner and leaf.spender:
            fx.allowances.append(
                AllowanceDelta(
                    owner=leaf.owner,
                    spender=leaf.spender,
                    token=leaf.token or "",
                    before=0,
                    after=leaf.amount or 0,
                )
            )
        elif leaf.kind is ActionKind.DELEGATE and leaf.delegate:
            fx.delegations.append(DelegationDelta(account=leaf.owner or "", delegate=leaf.delegate))
    return fx


class ChainSimulator:
    def __init__(self, rpc: RpcClient, mode: str = "local") -> None:
        self.rpc = rpc
        self.mode = mode
        self._lock = asyncio.Lock()  # one snapshot at a time on a shared chain

    async def simulate(self, proposal: Proposal, action: Action) -> Effects:
        if proposal.kind is not ProposalKind.TX:
            return declared_effects(action)
        started = time.perf_counter()
        async with self._lock:
            snap = await self.rpc.snapshot()
            try:
                fx = await self._execute(proposal.payload, action)
            finally:
                await self.rpc.revert(snap)
        fx.duration_ms = int((time.perf_counter() - started) * 1000)
        return fx

    async def _execute(self, p: dict[str, Any], action: Action) -> Effects:
        rpc = self.rpc
        sender = str(p["from"])
        to = p.get("to")
        await rpc.impersonate(sender)
        try:
            await rpc.set_balance(sender, max(await rpc.balance(sender), 10**20))
            delegations = []
            for auth in p.get("authorization_list") or []:
                delegate = str(auth["address"])
                await rpc.set_code(sender, "0xef0100" + delegate.removeprefix("0x").lower())
                delegations.append(DelegationDelta(account=sender, delegate=delegate))

            swaps = [leaf for leaf in action.leaves() if leaf.kind is ActionKind.SWAP]
            quotes: dict[int, int] = {}
            for i, s in enumerate(swaps):
                try:
                    out = await rpc.eth_call(
                        s.target or "",
                        _AMM.encode_call("getAmountOut", s.token_in, s.token_out, s.amount_in or 0),
                    )
                    quotes[i] = int(_AMM.decode_output("getAmountOut", out)[0])
                except RpcError:
                    quotes[i] = 0

            await rpc.call("anvil_setNextBlockBaseFeePerGas", ["0x0"])
            tx = {
                "from": sender,
                "value": hex(int(p.get("value", 0) or 0)),
                "data": p.get("data") or "0x",
                "gas": hex(5_000_000),
                "gasPrice": "0x0",
            }
            if to:
                tx["to"] = to
            try:
                tx_hash = await rpc.send_transaction(tx)
                rcpt = await rpc.wait(tx_hash)
            except RpcError as exc:
                return Effects(
                    mode="local",
                    reverted=True,
                    revert_reason=exc.message[:200],
                    delegations=delegations,
                )

            block = from_hex(rcpt["blockNumber"])
            status = from_hex(rcpt["status"])
            fx = Effects(
                mode="local",
                reverted=status != 1,
                gas_used=from_hex(rcpt["gasUsed"]),
                block_number=block,
                delegations=delegations,
            )
            if fx.reverted:
                return fx
            await self._diffs(fx, rcpt, sender, to, int(p.get("value", 0) or 0), block)
            if swaps:
                await self._swap_probes(fx, swaps, quotes, sender)
            return fx
        finally:
            await rpc.stop_impersonating(sender)

    async def _diffs(
        self, fx: Effects, rcpt: dict[str, Any], sender: str, to: str | None, value: int, block: int
    ) -> None:
        net: dict[tuple[str, str], int] = {}
        for log in rcpt.get("logs", []):
            topics = log.get("topics", [])
            if len(topics) == 3 and topics[0] == TRANSFER_TOPIC:
                token = log["address"]
                src, dst = topic_to_address(topics[1]), topic_to_address(topics[2])
                amt = int(log.get("data", "0x0") or "0x0", 16)
                net[(src, token)] = net.get((src, token), 0) - amt
                net[(dst, token)] = net.get((dst, token), 0) + amt
            elif len(topics) == 3 and topics[0] == APPROVAL_TOPIC:
                token = log["address"]
                owner, spender = topic_to_address(topics[1]), topic_to_address(topics[2])
                after = int(log.get("data", "0x0") or "0x0", 16)
                before_raw = await self.rpc.eth_call(
                    token, _ERC20.encode_call("allowance", owner, spender), block=hex(block - 1)
                )
                before = int(_ERC20.decode_output("allowance", before_raw)[0])
                fx.allowances.append(
                    AllowanceDelta(
                        owner=owner, spender=spender, token=token, before=before, after=after
                    )
                )
        for (addr, token), delta in net.items():
            if delta != 0:
                fx.assets.append(AssetDelta(address=addr, token=token, delta=delta))
        # Native: exact because the gas price is zero.
        watched = {sender} | ({to} if to else set())
        for addr in watched:
            before = await self.rpc.balance(addr, hex(block - 1))
            after = await self.rpc.balance(addr, hex(block))
            if after != before:
                fx.assets.append(AssetDelta(address=addr, token=NATIVE, delta=after - before))
        del value

    async def _swap_probes(
        self, fx: Effects, swaps: list[Action], quotes: dict[int, int], sender: str
    ) -> None:
        """Honeypot test (can the bought amount be sold back?) and transfer-tax measurement."""
        received: dict[str, int] = {}
        for d in fx.assets:
            if d.address.lower() == sender.lower() and d.delta > 0:
                received[d.token.lower()] = received.get(d.token.lower(), 0) + d.delta
        worst_tax = 0
        for i, s in enumerate(swaps):
            got = received.get((s.token_out or "").lower(), 0)
            quote = quotes.get(i, 0)
            if quote > 0 and got < quote:
                worst_tax = max(worst_tax, (quote - got) * 10_000 // quote)
            if got <= 0 or not s.token_out or not s.target:
                continue
            await self.rpc.call("anvil_setNextBlockBaseFeePerGas", ["0x0"])
            await self.rpc.send_and_wait(
                {
                    "from": sender,
                    "to": s.token_out,
                    "gasPrice": "0x0",
                    "data": _ERC20.encode_call("approve", s.target, got),
                }
            )
            try:
                await self.rpc.eth_call(
                    s.target,
                    _AMM.encode_call("swapExactIn", s.token_out, s.token_in, got, 0, sender),
                    sender=sender,
                )
                fx.honeypot_sell_reverted = bool(fx.honeypot_sell_reverted)
            except RpcError:
                fx.honeypot_sell_reverted = True
        fx.transfer_tax_bps = worst_tax
