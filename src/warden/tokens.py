"""HMAC decision tokens (ADR-0008).

``wdt1.<b64url(payload)>.<b64url(HMAC-SHA256(secret, payload))>`` where ``payload`` is the canonical
JSON of ``{decision_id, proposal_sha256, chain_id, expires_at, nonce}``.

Minted by the firewall for ``allow`` decisions only; verified by the signer. This module has no
dependencies on the rest of Warden so the signer can use it without importing the firewall.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime

from warden.clock import iso, parse_iso

PREFIX = "wdt1"


class TokenError(ValueError):
    """Why a token was refused. ``reason`` is one of the signer refusal labels."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class TokenPayload:
    decision_id: str
    proposal_sha256: str
    chain_id: int
    expires_at: str
    nonce: str

    def as_dict(self) -> dict[str, object]:
        return {
            "decision_id": self.decision_id,
            "proposal_sha256": self.proposal_sha256,
            "chain_id": self.chain_id,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _canonical(payload: TokenPayload) -> bytes:
    return json.dumps(payload.as_dict(), sort_keys=True, separators=(",", ":")).encode()


def mint(
    secret: bytes,
    *,
    decision_id: str,
    proposal_sha256: str,
    chain_id: int,
    expires_at: datetime,
    nonce: str | None = None,
) -> tuple[str, TokenPayload]:
    payload = TokenPayload(
        decision_id, proposal_sha256, chain_id, iso(expires_at), nonce or secrets.token_hex(16)
    )
    body = _canonical(payload)
    mac = hmac.new(secret, body, hashlib.sha256).digest()
    return f"{PREFIX}.{_b64(body)}.{_b64(mac)}", payload


def verify(secret: bytes, token: str, now: datetime) -> TokenPayload:
    """Check format, MAC and expiry. Nonce reuse and proposal binding are checked by the caller."""
    try:
        prefix, body_b64, mac_b64 = token.split(".")
    except ValueError as exc:
        raise TokenError("bad_mac", "malformed token") from exc
    if prefix != PREFIX:
        raise TokenError("bad_mac", "unknown token version")
    body = _unb64(body_b64)
    expected = hmac.new(secret, body, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _unb64(mac_b64)):
        raise TokenError("bad_mac")
    data = json.loads(body)
    payload = TokenPayload(
        str(data["decision_id"]),
        str(data["proposal_sha256"]),
        int(data["chain_id"]),
        str(data["expires_at"]),
        str(data["nonce"]),
    )
    if parse_iso(payload.expires_at) <= now:
        raise TokenError("expired", payload.expires_at)
    return payload
