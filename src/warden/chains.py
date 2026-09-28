"""Chain allowlist (invariant 5: testnets and a local chain only).

This module is imported by the signer, the firewall and the config. It has no dependencies so that
the allowlist can be audited in one place.
"""

from __future__ import annotations

from typing import Final

ANVIL: Final = 31337
BASE_SEPOLIA: Final = 84532
SEPOLIA: Final = 11155111

ALLOWED_CHAIN_IDS: Final[frozenset[int]] = frozenset({ANVIL, BASE_SEPOLIA, SEPOLIA})

CHAIN_NAMES: Final[dict[int, str]] = {
    ANVIL: "anvil",
    BASE_SEPOLIA: "base-sepolia",
    SEPOLIA: "sepolia",
}


class ChainNotAllowedError(ValueError):
    """Raised when any component is asked to work with a chain outside the allowlist."""

    def __init__(self, chain_id: int) -> None:
        super().__init__(
            f"chain id {chain_id} is not allowed; Warden only runs on "
            f"{sorted(ALLOWED_CHAIN_IDS)} (testnets and a local chain)"
        )
        self.chain_id = chain_id


def require_allowed(chain_id: int) -> int:
    """Return ``chain_id`` if it is allowed, otherwise raise :class:`ChainNotAllowedError`."""
    if chain_id not in ALLOWED_CHAIN_IDS:
        raise ChainNotAllowedError(chain_id)
    return chain_id


def chain_id_by_name(name: str) -> int:
    for cid, cname in CHAIN_NAMES.items():
        if cname == name:
            return cid
    raise ValueError(f"unknown chain {name!r}; choose one of {sorted(CHAIN_NAMES.values())}")
