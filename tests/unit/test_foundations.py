from __future__ import annotations

import pytest
from pydantic import ValidationError

from warden.canonical import canonical_json, canonical_sha256
from warden.chains import ALLOWED_CHAIN_IDS, ChainNotAllowedError, require_allowed
from warden.config import Settings
from warden.ids import new_id

MAINNET_IDS = [1, 8453, 10, 42161, 137, 56]


def test_allowlist_is_exactly_testnets_and_anvil() -> None:
    assert frozenset({31337, 84532, 11155111}) == ALLOWED_CHAIN_IDS


@pytest.mark.parametrize("chain_id", MAINNET_IDS)
def test_mainnet_ids_are_refused(chain_id: int) -> None:
    with pytest.raises(ChainNotAllowedError):
        require_allowed(chain_id)


@pytest.mark.parametrize("chain_id", MAINNET_IDS)
def test_settings_refuse_mainnet(chain_id: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, chain_id=chain_id)  # type: ignore[call-arg]


def test_canonical_json_is_order_independent() -> None:
    a = {"b": 1, "a": [1, 2, {"z": "é", "y": None}]}
    b = {"a": [1, 2, {"y": None, "z": "é"}], "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert canonical_json(a) == '{"a":[1,2,{"y":null,"z":"é"}],"b":1}'.encode()
    assert canonical_sha256(a) == canonical_sha256(b)


def test_ids_are_prefixed_and_sortable() -> None:
    first = new_id("dec", now_ms=1_000)
    second = new_id("dec", now_ms=2_000)
    assert first.startswith("dec_") and len(first) == 4 + 26
    assert first < second
    with pytest.raises(ValueError):
        new_id("nope")
