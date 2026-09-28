"""Canonical JSON and hashing.

Everything Warden hashes (mandates, proposals, policies, decision rows, token payloads) goes through
``canonical_json`` so that the same object always produces the same bytes.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel


def _default(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, bytes):
        return "0x" + obj.hex()
    if isinstance(obj, set | frozenset):
        return sorted(obj)
    raise TypeError(f"cannot canonicalise {type(obj).__name__}")


def canonical_json(obj: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8. Integers stay integers; floats are rejected upstream."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_default
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))
