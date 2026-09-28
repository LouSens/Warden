"""SQLite access through aiosqlite: WAL mode, foreign keys, busy timeout, explicit transactions."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite

Row = aiosqlite.Row


class Database:
    """A single connection used by one process. SQLite allows one writer at a time."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        self._conn: aiosqlite.Connection | None = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("database is not open")
        return self._conn

    async def open(self) -> Database:
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: we issue BEGIN/COMMIT ourselves.
        self._conn = await aiosqlite.connect(str(self.path), isolation_level=None)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        return self

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self) -> Database:
        return await self.open()

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """``BEGIN IMMEDIATE`` so that read-then-write sequences (hash chain, leases) are atomic."""
        conn = self.conn
        await conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            await conn.execute("ROLLBACK")
            raise
        else:
            await conn.execute("COMMIT")

    async def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> None:
        await self.conn.execute(sql, params)

    async def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        await self.conn.executemany(sql, rows)

    async def fetchone(
        self, sql: str, params: Sequence[Any] | dict[str, Any] = ()
    ) -> aiosqlite.Row | None:
        async with self.conn.execute(sql, params) as cur:
            return await cur.fetchone()

    async def fetchall(
        self, sql: str, params: Sequence[Any] | dict[str, Any] = ()
    ) -> list[aiosqlite.Row]:
        async with self.conn.execute(sql, params) as cur:
            return list(await cur.fetchall())

    async def scalar(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> Any:
        row = await self.fetchone(sql, params)
        return None if row is None else row[0]
