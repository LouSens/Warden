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


chain_app = typer.Typer(help="The local chain world.")
app.add_typer(chain_app, name="chain")


@chain_app.command("deploy")
def chain_deploy(
    reset: bool = typer.Option(False, help="anvil_reset first (fresh genesis)."),
    write: bool = typer.Option(False, help="Overwrite a differing deployment record."),
) -> None:
    """Deploy the WardenBench world; verify it matches contracts/deployments/anvil.json."""
    import json

    from warden.chain.rpc import RpcClient
    from warden.chain.world import WorldDeployer, deployment_path, is_deployed, render_record

    settings = get_settings()
    path = deployment_path("anvil")

    async def _run() -> int:
        rpc = RpcClient(settings.rpc_url)
        try:
            if reset:
                await rpc.reset()
            existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
            if existing is not None and not reset and await is_deployed(rpc, existing):
                typer.echo(f"already deployed (record {path})")
                return 0
            record = await WorldDeployer(rpc).deploy()
            text = render_record(record)
            if existing is not None and render_record(existing) != text and not write:
                typer.echo("deployment differs from the committed record; use --write to replace")
                return 1
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            typer.echo(f"deployed {len(record['contracts'])} contracts; record {path}")
            return 0
        finally:
            await rpc.aclose()

    raise typer.Exit(asyncio.run(_run()))


signer_app = typer.Typer(help="The signer process (holds the only key).")
policy_app = typer.Typer(help="Policy validation and impact dry-run.")
audit_app = typer.Typer(help="Audit log verification.")
app.add_typer(signer_app, name="signer")
app.add_typer(policy_app, name="policy")
app.add_typer(audit_app, name="audit")


@signer_app.command("serve")
def signer_serve(port: int = typer.Option(8201), host: str = typer.Option("127.0.0.1")) -> None:
    """Run the signer on 127.0.0.1 (never expose it)."""
    import uvicorn

    from warden.signer.app import create_signer_app

    if host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):  # noqa: S104 - 0.0.0.0 only inside a container
        raise typer.BadParameter("the signer binds to loopback only")
    uvicorn.run(create_signer_app(), host=host, port=port, log_level="warning")


@policy_app.command("validate")
def policy_validate(path: str = typer.Argument("policy.yaml")) -> None:
    """Validate a policy file."""
    from pathlib import Path

    from warden.policy.evaluator import PolicyInvalid, load_policy

    try:
        loaded = load_policy(Path(path).read_text(encoding="utf-8"))
    except PolicyInvalid as exc:
        for e in exc.errors:
            typer.echo(f"error: {e}")
        raise typer.Exit(1) from exc
    typer.echo(f"valid; sha256 {loaded.sha256}; {len(loaded.policy.rules)} rules")


@policy_app.command("diff")
def policy_diff(path: str) -> None:
    """Impact dry-run: list recorded decisions that would change under a candidate policy."""
    from pathlib import Path

    from warden.chain.registry import Registries
    from warden.chain.world import load_world
    from warden.firewall.dryrun import dry_run
    from warden.firewall.store import FirewallStore
    from warden.policy.evaluator import load_policy
    from warden.storage.database import Database

    settings = get_settings()
    loaded = load_policy(Path(path).read_text(encoding="utf-8"))

    async def _run() -> dict[str, object]:
        async with Database(settings.db_path) as db:
            return await dry_run(FirewallStore(db), loaded, Registries.from_world(load_world()))

    report = asyncio.run(_run())
    for c in report["changed"]:  # type: ignore[attr-defined]
        typer.echo(f"{c['proposal_id']}  {c['old']:<9} -> {c['new']:<9} {', '.join(c['rules'])}")
    typer.echo(
        f"{len(report['changed'])} of {report['evaluated']} decisions would change "  # type: ignore[arg-type]
        f"{report['counts']}"
    )


@audit_app.command("verify")
def audit_verify(signer: bool = typer.Option(False, help="Also cross-check signer.db.")) -> None:
    """Walk the decision hash chain; optionally check every signature has an allow decision."""
    from warden.firewall.store import FirewallStore
    from warden.storage.database import Database

    settings = get_settings()

    async def _run() -> int:
        async with Database(settings.db_path) as db:
            store = FirewallStore(db)
            report = await store.verify_chain()
            typer.echo(f"decision chain: {report}")
            code = 0 if report["ok"] else 1
            if signer and settings.signer_db_path.exists():
                async with Database(settings.signer_db_path) as sdb:
                    for row in await sdb.fetchall("SELECT id, decision_id FROM signature"):
                        d = await store.get_decision(row["decision_id"])
                        if d is None or d.verdict.value != "allow":
                            typer.echo(f"signature {row['id']} has no allow decision")
                            code = 1
            return code

    raise typer.Exit(asyncio.run(_run()))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
