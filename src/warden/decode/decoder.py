"""Decode proposals into typed actions.

The decoder is deliberately conservative: anything it does not recognise becomes ``unknown`` (and
the ``unknown_calldata`` check fires), and a type-4 transaction's ``authorization_list`` is always
decoded, whatever the calldata says.
"""

from __future__ import annotations

from typing import Any, Protocol

from eth_abi.abi import decode as abi_decode

from warden.chain.abi import checksum, selector_of
from warden.firewall.models import NATIVE, Action, ActionKind, Proposal, ProposalKind

SEL = {
    "transfer": selector_of("transfer(address,uint256)"),
    "approve": selector_of("approve(address,uint256)"),
    "transferFrom": selector_of("transferFrom(address,address,uint256)"),
    "setApprovalForAll": selector_of("setApprovalForAll(address,bool)"),
    "permit": selector_of("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"),
    "swapExactIn": selector_of("swapExactIn(address,address,uint256,uint256,address)"),
    "multicall": selector_of("multicall(bytes[])"),
}


class Decoder(Protocol):
    def decode(self, proposal: Proposal) -> Action: ...


def _hex(data: str) -> bytes:
    return bytes.fromhex(data.removeprefix("0x")) if data else b""


def _args(types: list[str], data: bytes) -> tuple[Any, ...]:
    return tuple(abi_decode(types, data[4:]))


class CallDecoder:
    def decode(self, proposal: Proposal) -> Action:
        try:
            if proposal.kind is ProposalKind.TX:
                return self._tx(proposal.payload)
            if proposal.kind is ProposalKind.TYPED_DATA:
                return self._typed(proposal.payload)
            if proposal.kind is ProposalKind.AUTH_7702:
                p = proposal.payload
                return Action(
                    kind=ActionKind.DELEGATE,
                    delegate=checksum(p["address"]),
                    owner=checksum(p["from"]),
                )
            if proposal.kind is ProposalKind.X402:
                return self._x402(proposal.payload)
        except (KeyError, ValueError, TypeError) as exc:
            return Action(kind=ActionKind.UNKNOWN, note=f"malformed {proposal.kind.value}: {exc}")
        return Action(kind=ActionKind.UNKNOWN, note="unsupported proposal kind")

    # ------------------------------------------------------------------ transactions
    def _tx(self, p: dict[str, Any]) -> Action:
        sender = checksum(p["from"])
        to = checksum(p["to"]) if p.get("to") else None
        value = int(p.get("value", 0) or 0)
        data = _hex(p.get("data", "") or "")
        actions: list[Action] = []

        for auth in p.get("authorization_list") or []:
            actions.append(
                Action(kind=ActionKind.DELEGATE, delegate=checksum(auth["address"]), owner=sender)
            )
        if to is None:
            actions.append(Action(kind=ActionKind.UNKNOWN, note="contract creation"))
        else:
            if value > 0:
                actions.append(
                    Action(kind=ActionKind.TRANSFER, target=to, token=NATIVE, to=to, amount=value)
                )
            if data:
                actions.append(self._call(to, data, sender))
        if not actions:
            return Action(kind=ActionKind.UNKNOWN, note="empty transaction")
        return (
            actions[0]
            if len(actions) == 1
            else Action(kind=ActionKind.BATCH, target=to, children=actions)
        )

    def _call(self, to: str, data: bytes, sender: str, depth: int = 0) -> Action:
        sel = "0x" + data[:4].hex()
        try:
            if sel == SEL["transfer"]:
                dst, amount = _args(["address", "uint256"], data)
                return Action(
                    kind=ActionKind.TRANSFER,
                    target=to,
                    token=to,
                    to=checksum(dst),
                    amount=int(amount),
                    selector=sel,
                )
            if sel == SEL["transferFrom"]:
                src, dst, amount = _args(["address", "address", "uint256"], data)
                return Action(
                    kind=ActionKind.TRANSFER,
                    target=to,
                    token=to,
                    owner=checksum(src),
                    to=checksum(dst),
                    amount=int(amount),
                    selector=sel,
                )
            if sel == SEL["approve"]:
                spender, amount = _args(["address", "uint256"], data)
                return Action(
                    kind=ActionKind.APPROVE,
                    target=to,
                    token=to,
                    owner=sender,
                    spender=checksum(spender),
                    amount=int(amount),
                    selector=sel,
                )
            if sel == SEL["setApprovalForAll"]:
                op, approved = _args(["address", "bool"], data)
                return Action(
                    kind=ActionKind.SET_APPROVAL_FOR_ALL,
                    target=to,
                    token=to,
                    owner=sender,
                    spender=checksum(op),
                    approved=bool(approved),
                    selector=sel,
                )
            if sel == SEL["permit"]:
                owner, spender, value, deadline, *_ = _args(
                    ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
                    data,
                )
                return Action(
                    kind=ActionKind.PERMIT,
                    target=to,
                    token=to,
                    owner=checksum(owner),
                    spender=checksum(spender),
                    amount=int(value),
                    deadline=int(deadline),
                    selector=sel,
                )
            if sel == SEL["swapExactIn"]:
                t_in, t_out, amount_in, min_out, recipient = _args(
                    ["address", "address", "uint256", "uint256", "address"], data
                )
                return Action(
                    kind=ActionKind.SWAP,
                    target=to,
                    token_in=checksum(t_in),
                    token_out=checksum(t_out),
                    amount_in=int(amount_in),
                    min_out=int(min_out),
                    to=checksum(recipient),
                    selector=sel,
                )
            if sel == SEL["multicall"] and depth < 3:
                (calls,) = _args(["bytes[]"], data)
                children = [self._call(to, bytes(c), sender, depth + 1) for c in calls]
                return Action(kind=ActionKind.BATCH, target=to, children=children, selector=sel)
        except Exception as exc:
            return Action(
                kind=ActionKind.UNKNOWN,
                target=to,
                selector=sel,
                note=f"undecodable arguments: {type(exc).__name__}",
            )
        return Action(kind=ActionKind.UNKNOWN, target=to, selector=sel, note="unknown selector")

    # ------------------------------------------------------------------ typed data
    def _typed(self, p: dict[str, Any]) -> Action:
        td = p["typed_data"]
        primary = td.get("primaryType")
        msg = td.get("message", {})
        domain = td.get("domain", {})
        verifying = domain.get("verifyingContract")
        if primary == "Permit":
            return Action(
                kind=ActionKind.PERMIT,
                target=checksum(verifying),
                token=checksum(verifying),
                owner=checksum(msg["owner"]),
                spender=checksum(msg["spender"]),
                amount=int(msg["value"]),
                deadline=int(msg["deadline"]),
            )
        if primary in {"PermitSingle", "PermitBatch"}:
            details = msg["details"] if primary == "PermitSingle" else msg["details"][0]
            return Action(
                kind=ActionKind.PERMIT2,
                target=checksum(verifying),
                token=checksum(details["token"]),
                spender=checksum(msg["spender"]),
                amount=int(details["amount"]),
                deadline=int(msg["sigDeadline"]),
                owner=checksum(p["from"]),
            )
        if primary == "PermitTransferFrom":
            return Action(
                kind=ActionKind.PERMIT2,
                target=checksum(verifying),
                token=checksum(msg["permitted"]["token"]),
                spender=checksum(msg["spender"]),
                amount=int(msg["permitted"]["amount"]),
                deadline=int(msg["deadline"]),
                owner=checksum(p["from"]),
            )
        if primary == "TransferWithAuthorization":
            return Action(
                kind=ActionKind.TRANSFER,
                target=checksum(verifying),
                token=checksum(verifying),
                owner=checksum(msg["from"]),
                to=checksum(msg["to"]),
                amount=int(msg["value"]),
                deadline=int(msg["validBefore"]),
                nonce=str(msg["nonce"]),
                note="EIP-3009 authorization",
            )
        return Action(kind=ActionKind.UNKNOWN, note=f"unknown typed data {primary!r}")

    # ------------------------------------------------------------------ x402
    def _x402(self, p: dict[str, Any]) -> Action:
        req = p["requirements"]
        return Action(
            kind=ActionKind.X402,
            target=checksum(req["asset"]),
            token=checksum(req["asset"]),
            owner=checksum(p["from"]),
            to=checksum(req["pay_to"]),
            amount=int(req["amount"]),
            service=str(req.get("service", "")),
            nonce=str(req["nonce"]),
            deadline=int(req["valid_before"]),
        )
