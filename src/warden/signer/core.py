"""The signer: verify a decision token, then sign and (for transactions) broadcast.

Checks, in order (docs/architecture.md §5): MAC and expiry; proposal hash bound to the token; chain
allowlist and chain match; sender is the signer's own account; hard value ceilings; single-use nonce
(``UNIQUE`` in the signer's own database, reserved before anything is signed).

This module must not import the LLM, agent, bench or policy packages (import-linter enforces it).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

from warden.canonical import canonical_sha256
from warden.chain.abi import checksum, load_artifact
from warden.chain.rpc import RpcClient, from_hex
from warden.chains import ALLOWED_CHAIN_IDS
from warden.clock import Clock, iso
from warden.decode.decoder import CallDecoder
from warden.firewall.models import ActionKind, Proposal, ProposalKind
from warden.ids import new_id
from warden.storage.database import Database
from warden.tokens import TokenError, verify

_TOKEN = load_artifact("AuthToken")


class SignerRefused(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class SignResult:
    signature_id: str
    decision_id: str
    tx_hash: str | None = None
    signature: str | None = None
    receipt_status: int | None = None
    signed: dict[str, Any] | None = None  # e.g. v/r/s parts for typed data, auth tuple for 7702


def eip3009_typed_data(
    chain_id: int,
    token: str,
    token_name: str,
    frm: str,
    to: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: str,
) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": "1",
            "chainId": chain_id,
            "verifyingContract": token,
        },
        "message": {
            "from": frm,
            "to": to,
            "value": value,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": nonce,
        },
    }


class Signer:
    def __init__(
        self,
        *,
        key: str,
        token_secret: bytes,
        db: Database,
        rpc: RpcClient,
        clock: Clock,
        max_native_wei: int,
        max_token_amount: int,
    ) -> None:
        self._account = Account.from_key(key)
        self._secret = token_secret
        self.db = db
        self.rpc = rpc
        self.clock = clock
        self.max_native_wei = max_native_wei
        self.max_token_amount = max_token_amount
        self._decoder = CallDecoder()

    @property
    def address(self) -> str:
        return str(self._account.address)

    # ------------------------------------------------------------------ checks
    def _check(self, token: str, proposal: Proposal, now: datetime) -> tuple[str, str]:
        try:
            payload = verify(self._secret, token, now)
        except TokenError as exc:
            raise SignerRefused(exc.reason, str(exc)) from exc
        if canonical_sha256(proposal.model_dump(mode="json")) != payload.proposal_sha256:
            raise SignerRefused("hash_mismatch", "proposal differs from the allowed one")
        if proposal.chain_id not in ALLOWED_CHAIN_IDS or payload.chain_id not in ALLOWED_CHAIN_IDS:
            raise SignerRefused("chain", f"chain {proposal.chain_id} is not allowed")
        if proposal.chain_id != payload.chain_id:
            raise SignerRefused("chain", "token chain differs from proposal chain")
        if checksum(proposal.sender) != self.address:
            raise SignerRefused("hash_mismatch", "proposal sender is not the signer's account")
        action = self._decoder.decode(proposal)
        native = int(proposal.payload.get("value", 0) or 0)
        if native > self.max_native_wei:
            raise SignerRefused("ceiling", "native value above the signer ceiling")
        for leaf in action.leaves():
            amount = max(leaf.amount or 0, leaf.amount_in or 0)
            unlimited_approval = leaf.kind in (
                ActionKind.APPROVE,
                ActionKind.PERMIT,
                ActionKind.PERMIT2,
            )
            if amount > self.max_token_amount and not unlimited_approval:
                raise SignerRefused("ceiling", "token amount above the signer ceiling")
        return payload.decision_id, payload.nonce

    async def _reserve(self, decision_id: str, nonce: str, proposal: Proposal) -> str:
        sid = new_id("sig")
        try:
            await self.db.execute(
                "INSERT INTO signature(id, decision_id, token_nonce, chain_id, payload_sha256,"
                " created_at) VALUES (?,?,?,?,?,?)",
                (
                    sid,
                    decision_id,
                    nonce,
                    proposal.chain_id,
                    canonical_sha256(proposal.model_dump(mode="json")),
                    iso(self.clock.now()),
                ),
            )
        except Exception as exc:  # sqlite3.IntegrityError: the nonce was used before
            if "UNIQUE" in str(exc):
                raise SignerRefused("reused", "decision token already used") from exc
            raise
        return sid

    # ------------------------------------------------------------------ signing
    async def sign(self, token: str, proposal: Proposal) -> SignResult:
        decision_id, nonce = self._check(token, proposal, self.clock.now())
        sid = await self._reserve(decision_id, nonce, proposal)
        if proposal.kind is ProposalKind.TX:
            return await self._sign_tx(sid, decision_id, proposal)
        if proposal.kind is ProposalKind.TYPED_DATA:
            signed = Account.sign_typed_data(
                self._account.key, full_message=proposal.payload["typed_data"]
            )
            sig = "0x" + bytes(signed.signature).hex()
            return SignResult(
                sid,
                decision_id,
                signature=sig,
                signed={"v": signed.v, "r": hex(signed.r), "s": hex(signed.s)},
            )
        if proposal.kind is ProposalKind.X402:
            return await self._sign_x402(sid, decision_id, proposal)
        if proposal.kind is ProposalKind.AUTH_7702:
            p = proposal.payload
            auth = Account.sign_authorization(
                {
                    "chainId": proposal.chain_id,
                    "address": checksum(p["address"]),
                    "nonce": int(p["nonce"]),
                },
                self._account.key,
            )
            return SignResult(
                sid,
                decision_id,
                signed={
                    "chain_id": auth.chain_id,
                    "address": auth.address,
                    "nonce": auth.nonce,
                    "y_parity": auth.y_parity,
                    "r": hex(auth.r),
                    "s": hex(auth.s),
                },
            )
        raise SignerRefused("hash_mismatch", "unsupported proposal kind")

    async def _sign_tx(self, sid: str, decision_id: str, proposal: Proposal) -> SignResult:
        p = proposal.payload
        rpc = self.rpc
        nonce = await rpc.nonce(self.address, "pending")
        base = from_hex((await rpc.get_block("latest")).get("baseFeePerGas", "0x0"))
        tx: dict[str, Any] = {
            "chainId": proposal.chain_id,
            "nonce": nonce,
            "to": checksum(p["to"]),
            "value": int(p.get("value", 0) or 0),
            "data": p.get("data") or "0x",
            "maxFeePerGas": base * 2 + 10**9,
            "maxPriorityFeePerGas": 10**9,
        }
        auths = []
        for i, a in enumerate(p.get("authorization_list") or []):
            # Self-sponsored: the authorization nonce is the account nonce after this tx's nonce.
            auths.append(
                Account.sign_authorization(
                    {
                        "chainId": proposal.chain_id,
                        "address": checksum(a["address"]),
                        "nonce": nonce + 1 + i,
                    },
                    self._account.key,
                )
            )
        if auths:
            tx["authorizationList"] = auths
        gas_probe = {
            "from": self.address,
            "to": tx["to"],
            "value": hex(tx["value"]),
            "data": tx["data"],
        }
        try:
            tx["gas"] = int(await rpc.estimate_gas(gas_probe) * 1.3) + 50_000 * len(auths)
        except Exception:
            tx["gas"] = 500_000
        signed = Account.sign_transaction(tx, self._account.key)
        tx_hash = await rpc.send_raw("0x" + bytes(signed.raw_transaction).hex())
        rcpt = await rpc.wait(tx_hash)
        status = from_hex(rcpt.get("status"))
        await self.db.execute(
            "UPDATE signature SET tx_hash=?, broadcast_at=?, receipt_status=? WHERE id=?",
            (tx_hash, iso(self.clock.now()), status, sid),
        )
        return SignResult(sid, decision_id, tx_hash=tx_hash, receipt_status=status)

    async def _sign_x402(self, sid: str, decision_id: str, proposal: Proposal) -> SignResult:
        req = proposal.payload["requirements"]
        asset = checksum(req["asset"])
        name_raw = await self.rpc.eth_call(asset, _TOKEN.encode_call("name"))
        token_name = str(_TOKEN.decode_output("name", name_raw)[0])
        td = eip3009_typed_data(
            proposal.chain_id,
            asset,
            token_name,
            self.address,
            checksum(req["pay_to"]),
            int(req["amount"]),
            0,
            int(req["valid_before"]),
            str(req["nonce"]),
        )
        signed = Account.sign_typed_data(self._account.key, full_message=td)
        return SignResult(
            sid,
            decision_id,
            signature="0x" + bytes(signed.signature).hex(),
            signed={
                "v": signed.v,
                "r": "0x" + signed.r.to_bytes(32, "big").hex(),
                "s": "0x" + signed.s.to_bytes(32, "big").hex(),
                "typed_data": td,
            },
        )

    async def signature_for(self, decision_id: str) -> dict[str, Any] | None:
        row = await self.db.fetchone("SELECT * FROM signature WHERE decision_id=?", (decision_id,))
        return dict(row) if row is not None else None


def recover_typed(signature: str, typed_data: dict[str, Any]) -> str:
    """Helper for tests and the mock facilitator."""
    return str(
        Account.recover_message(encode_typed_data(full_message=typed_data), signature=signature)
    )
