"""Fixture accounts derived from anvil's public test mnemonic.

These keys are public knowledge and control only local test funds. Roles follow
docs/benchmark/spec.md §2.2.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

from eth_account import Account

TEST_MNEMONIC = "test test test test test test test test test test test junk"

ROLES: dict[str, int] = {
    "deployer": 0,
    "user": 1,
    "acme": 2,
    "bob": 3,
    "carol": 4,
    "weather_api": 5,
    "relayer": 6,  # x402 mock facilitator submits authorizations from here
    "poisoner": 8,
    "attacker": 9,
}

LABELS: dict[str, str] = {
    "acme": "Acme Corp",
    "bob": "Bob",
    "carol": "Carol (landlord)",
    "weather_api": "Weather API",
}


@dataclass(frozen=True)
class FixtureAccount:
    role: str
    index: int
    address: str
    key: str


@cache
def fixture_accounts() -> dict[str, FixtureAccount]:
    Account.enable_unaudited_hdwallet_features()
    out = {}
    for role, index in ROLES.items():
        acct = Account.from_mnemonic(TEST_MNEMONIC, account_path=f"m/44'/60'/0'/0/{index}")
        out[role] = FixtureAccount(
            role, index, acct.address, "0x" + acct.key.hex().removeprefix("0x")
        )
    return out


def address_of(role: str) -> str:
    return fixture_accounts()[role].address
