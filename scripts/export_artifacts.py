"""Copy the ABI and bytecode of each WardenBench contract from forge output into contracts/out/.

Usage (after `forge build` in contracts/):  python scripts/export_artifacts.py [--check]
`--check` fails if the committed artifacts differ from a fresh build (CI uses it).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORGE_OUT = ROOT / "contracts" / ".forge-out"
OUT = ROOT / "contracts" / "out"

SOURCES = {
    "AuthToken": "Tokens.sol",
    "PermitToken": "Tokens.sol",
    "TestToken": "Tokens.sol",
    "HoneypotToken": "Tokens.sol",
    "FeeOnTransferToken": "Tokens.sol",
    "MiniAMM": "MiniAMM.sol",
    "DrainerSpender": "Attackers.sol",
    "Sweeper7702": "Attackers.sol",
}


def render(name: str, source: str) -> str:
    raw = json.loads((FORGE_OUT / source / f"{name}.json").read_text(encoding="utf-8"))
    compact = {
        "contractName": name,
        "source": f"contracts/src/{source}",
        "abi": raw["abi"],
        "bytecode": raw["bytecode"]["object"],
        "deployedBytecode": raw["deployedBytecode"]["object"],
    }
    return json.dumps(compact, indent=1, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    stale = []
    for name, source in SOURCES.items():
        text = render(name, source)
        target = OUT / f"{name}.json"
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            target.write_text(text, encoding="utf-8", newline="\n")
    if stale:
        print(f"committed artifacts differ from the build: {stale}")
        return 1
    print("artifacts " + ("match" if args.check else f"written to {OUT}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
