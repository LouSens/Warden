"""The ``warden`` command line."""

from __future__ import annotations

import asyncio

import typer

from warden import __version__
from warden.config import get_settings

app = typer.Typer(help="Warden: transaction firewall and WardenBench.", no_args_is_help=True)
secrets_app = typer.Typer(help="Local secrets (signer key, decision-token secret).")
db_app = typer.Typer(help="Database maintenance.")
app.add_typer(secrets_app, name="secrets")
app.add_typer(db_app, name="db")


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command()
def doctor() -> None:
    """Preflight checks; each failed check names its fix."""
    from warden.doctor import run_checks

    failed_required = False
    for c in run_checks(get_settings()):
        mark = "ok  " if c.ok else ("FAIL" if c.required else "warn")
        line = f"[{mark}] {c.name}: {c.detail}"
        if not c.ok and c.fix:
            line += f"  -> {c.fix}"
        typer.echo(line)
        failed_required |= c.required and not c.ok
    raise typer.Exit(1 if failed_required else 0)


@secrets_app.command("init")
def secrets_init(overwrite: bool = typer.Option(False, help="Replace existing secrets.")) -> None:
    """Create data/secrets/signer.key and decision_token.key if missing."""
    from warden.secrets import init_secrets

    written = init_secrets(get_settings().secrets_dir, overwrite=overwrite)
    for p in written:
        typer.echo(f"wrote {p}")
    if not written:
        typer.echo("secrets already present")


@db_app.command("migrate")
def db_migrate() -> None:
    """Apply pending migrations to data/warden.db and data/signer/signer.db."""
    from warden.storage.database import Database
    from warden.storage.migrate import migrate

    settings = get_settings()

    async def _run() -> None:
        for schema, path in (("warden", settings.db_path), ("signer", settings.signer_db_path)):
            async with Database(path) as db:
                done = await migrate(db, schema)
                typer.echo(f"{schema}: applied {done or 'nothing'}")

    asyncio.run(_run())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
