"""Local secrets: the signer key and the decision-token secret.

Both live in ``data/secrets/`` (git-ignored). The API process reads only the token secret; the signer
reads both. The agent process never reads either.

The local-chain signer key is anvil's public test account 1. It controls only local test funds and is
refused on any chain outside the allowlist by the signer itself.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path

# anvil account 1 from the public test mnemonic ("test test ... junk"). Public; local funds only.
ANVIL_USER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ANVIL_USER_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

SIGNER_KEY_FILE = "signer.key"
TOKEN_KEY_FILE = "decision_token.key"  # noqa: S105 - a file name, not a secret
TESTNET_KEY_FILE = "testnet_signer.key"


def _write_private(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):  # Windows ignores POSIX modes; data/ is git-ignored anyway
        os.chmod(path, 0o600)


def init_secrets(secrets_dir: Path, *, overwrite: bool = False) -> list[Path]:
    """Create missing secrets. Returns the files written."""
    written = []
    signer = secrets_dir / SIGNER_KEY_FILE
    token = secrets_dir / TOKEN_KEY_FILE
    if overwrite or not signer.exists():
        _write_private(signer, ANVIL_USER_KEY)
        written.append(signer)
    if overwrite or not token.exists():
        _write_private(token, secrets.token_hex(32))
        written.append(token)
    return written


def read_token_secret(secrets_dir: Path) -> bytes:
    return bytes.fromhex((secrets_dir / TOKEN_KEY_FILE).read_text(encoding="utf-8").strip())


def read_signer_key(secrets_dir: Path, *, testnet: bool = False) -> str:
    name = TESTNET_KEY_FILE if testnet else SIGNER_KEY_FILE
    return (secrets_dir / name).read_text(encoding="utf-8").strip()
