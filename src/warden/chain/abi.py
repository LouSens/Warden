"""Compiled contract artifacts and ABI encoding/decoding."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from eth_abi.abi import decode as abi_decode
from eth_abi.abi import encode as abi_encode
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak

ARTIFACT_NAMES = (
    "AuthToken",
    "PermitToken",
    "TestToken",
    "HoneypotToken",
    "FeeOnTransferToken",
    "MiniAMM",
    "DrainerSpender",
    "Sweeper7702",
)


def contracts_dir() -> Path:
    """``contracts/`` at the repository root (the package is used from a source checkout)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "contracts" / "out"
        if candidate.is_dir():
            return candidate.parent
    return Path("contracts").resolve()


def _type_str(param: dict[str, Any]) -> str:
    t = str(param["type"])
    if t.startswith("tuple"):
        inner = ",".join(_type_str(c) for c in param["components"])
        return f"({inner}){t[5:]}"
    return t


@dataclass(frozen=True)
class AbiFunction:
    name: str
    inputs: tuple[str, ...]
    input_names: tuple[str, ...]
    outputs: tuple[str, ...]

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(self.inputs)})"

    @property
    def selector(self) -> bytes:
        return keccak(text=self.signature)[:4]


@dataclass(frozen=True)
class AbiEvent:
    name: str
    inputs: tuple[str, ...]
    input_names: tuple[str, ...]
    indexed: tuple[bool, ...]

    @property
    def topic(self) -> str:
        return "0x" + keccak(text=f"{self.name}({','.join(self.inputs)})").hex()


@dataclass(frozen=True)
class Artifact:
    name: str
    abi: list[dict[str, Any]]
    bytecode: str
    deployed_bytecode: str
    functions: dict[str, AbiFunction] = field(default_factory=dict)
    events: dict[str, AbiEvent] = field(default_factory=dict)

    @staticmethod
    def from_json(data: dict[str, Any]) -> Artifact:
        fns: dict[str, AbiFunction] = {}
        evs: dict[str, AbiEvent] = {}
        for item in data["abi"]:
            if item.get("type") == "function":
                fns[item["name"]] = AbiFunction(
                    item["name"],
                    tuple(_type_str(i) for i in item["inputs"]),
                    tuple(i.get("name", "") for i in item["inputs"]),
                    tuple(_type_str(o) for o in item.get("outputs", [])),
                )
            elif item.get("type") == "event":
                evs[item["name"]] = AbiEvent(
                    item["name"],
                    tuple(_type_str(i) for i in item["inputs"]),
                    tuple(i.get("name", "") for i in item["inputs"]),
                    tuple(bool(i.get("indexed")) for i in item["inputs"]),
                )
        return Artifact(
            data["contractName"], data["abi"], data["bytecode"], data["deployedBytecode"], fns, evs
        )

    def encode_call(self, fn_name: str, *args: Any) -> str:
        fn = self.functions[fn_name]
        return "0x" + (fn.selector + abi_encode(list(fn.inputs), list(args))).hex()

    def decode_output(self, fn_name: str, data: str) -> tuple[Any, ...]:
        fn = self.functions[fn_name]
        return tuple(abi_decode(list(fn.outputs), bytes.fromhex(data.removeprefix("0x"))))

    def deploy_data(self, ctor_types: list[str], *args: Any) -> str:
        return self.bytecode + abi_encode(ctor_types, list(args)).hex()


@cache
def load_artifact(name: str) -> Artifact:
    path = contracts_dir() / "out" / f"{name}.json"
    return Artifact.from_json(json.loads(path.read_text(encoding="utf-8")))


def checksum(address: str) -> str:
    return str(to_checksum_address(address))


def selector_of(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


def topic_of(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


TRANSFER_TOPIC = topic_of("Transfer(address,address,uint256)")
APPROVAL_TOPIC = topic_of("Approval(address,address,uint256)")


def topic_to_address(topic: str) -> str:
    return checksum("0x" + topic[-40:])
