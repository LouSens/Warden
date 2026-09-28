"""Preflight checks. Same as `warden doctor`; kept as a script so it runs before `pip install -e .`."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "src")
)  # before the package is installed

from warden.cli import app

if __name__ == "__main__":
    app(["doctor"])
