"""Numbered SQL migrations with checksums and a backup before migrating.

Rules, each for a specific failure:

* an existing database with pending migrations is copied with ``VACUUM INTO`` first;
* each migration runs in its own transaction;
* the checksum of every applied migration is recorded; an edited migration is refused;
* a database that has migrations this code does not know (a newer database) is refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from warden.canonical import sha256_hex
from warden.storage.database import Database

MIGRATIONS_ROOT = Path(__file__).parent / "migrations"
_NAME = re.compile(r"^(\d{3})_([a-z0-9_]+)\.sql$")


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return sha256_hex(self.sql.replace("\r\n", "\n"))


def load_migrations(directory: Path) -> list[Migration]:
    out = []
    for path in sorted(directory.glob("*.sql")):
        m = _NAME.match(path.name)
        if not m:
            raise MigrationError(f"bad migration file name: {path.name}")
        out.append(Migration(int(m.group(1)), m.group(2), path.read_text(encoding="utf-8")))
    versions = [m.version for m in out]
    if versions != list(range(1, len(out) + 1)):
        raise MigrationError(f"migrations must be numbered 001.. without gaps, got {versions}")
    return out


async def migrate(db: Database, schema: str) -> list[int]:
    """Apply pending migrations of ``schema`` (``warden`` or ``signer``). Returns applied versions."""
    migrations = load_migrations(MIGRATIONS_ROOT / schema)
    await db.execute(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL,"
        " applied_at TEXT NOT NULL)"
    )
    applied = {
        int(r["version"]): str(r["checksum"])
        for r in await db.fetchall("SELECT version, checksum FROM schema_version")
    }
    known = {m.version for m in migrations}
    newer = sorted(v for v in applied if v not in known)
    if newer:
        raise MigrationError(f"database has migrations {newer} unknown to this code (newer db?)")
    for m in migrations:
        if m.version in applied and applied[m.version] != m.checksum:
            raise MigrationError(f"migration {m.version:03d}_{m.name} was edited after applying")

    pending = [m for m in migrations if m.version not in applied]
    if not pending:
        return []

    if applied and str(db.path) != ":memory:":
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = db.path.with_name(f"{db.path.stem}.backup-{stamp}.db")
        await db.execute("VACUUM INTO ?", (str(backup),))

    done = []
    for m in pending:
        async with db.transaction() as conn:
            for statement in split_sql(m.sql):
                await conn.execute(statement)
            await conn.execute(
                "INSERT INTO schema_version(version, name, checksum, applied_at) VALUES (?,?,?,?)",
                (m.version, m.name, m.checksum, datetime.now(UTC).isoformat()),
            )
        done.append(m.version)
    return done


def split_sql(sql: str) -> list[str]:
    """Split a migration into statements, keeping ``CREATE TRIGGER ... BEGIN ... END;`` intact."""
    statements: list[str] = []
    buf: list[str] = []
    in_trigger = False
    for line in sql.replace("\r\n", "\n").split("\n"):
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith("--")):
            continue
        buf.append(line)
        code = stripped.split("--", 1)[0].rstrip()
        upper = code.upper()
        if upper.startswith("CREATE TRIGGER"):
            in_trigger = True
        if in_trigger:
            if upper.endswith("END;"):
                statements.append("\n".join(buf).strip().rstrip(";"))
                buf, in_trigger = [], False
        elif code.endswith(";"):
            statements.append("\n".join(buf).strip().rstrip(";"))
            buf = []
    if buf and "".join(buf).strip():
        statements.append("\n".join(buf).strip().rstrip(";"))
    return statements
