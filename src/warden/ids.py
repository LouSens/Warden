"""Prefixed, time-sortable identifiers (ULID layout, Crockford base32)."""

from __future__ import annotations

import secrets
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

PREFIXES = frozenset(
    {"man", "ses", "prp", "dec", "apr", "sig", "run", "eps", "abk", "job", "req", "fnd"}
)


def _b32(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(out))


def ulid(now_ms: int | None = None) -> str:
    ms = int(time.time() * 1000) if now_ms is None else now_ms
    return _b32(ms, 10) + _b32(secrets.randbits(80), 16)


def new_id(prefix: str, now_ms: int | None = None) -> str:
    if prefix not in PREFIXES:
        raise ValueError(f"unknown id prefix {prefix!r}")
    return f"{prefix}_{ulid(now_ms)}"
