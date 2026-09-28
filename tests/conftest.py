from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from warden.clock import FixedClock
from warden.config import Settings
from warden.storage.database import Database
from warden.storage.migrate import migrate


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Hermetic settings: temp data dir, no .env, no provider keys, no cache."""
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        groq_api_key=None,
        llm_cache=False,
        log_json=True,
    )


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC))


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(tmp_path / "warden.db")
    await database.open()
    await migrate(database, "warden")
    yield database
    await database.close()
