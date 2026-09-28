"""Composition root: builds and owns every long-lived component of the API process."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import asdict
from typing import Any

import httpx

from warden import __version__
from warden.chain.history import HistoryIndex
from warden.chain.registry import Registries
from warden.chain.rpc import RpcClient
from warden.chain.world import World, deployment_path, load_world
from warden.clock import Clock, SystemClock
from warden.config import Settings
from warden.firewall.pipeline import CONFIGS, Firewall
from warden.firewall.store import FirewallStore
from warden.intent.judge import IntentJudge
from warden.jobs.queue import JobQueue
from warden.jobs.worker import Handler, Worker
from warden.llm.base import ChatModel, ProviderUnavailable
from warden.llm.ratelimit import LimiterRegistry
from warden.llm.router import build_chat_model
from warden.logging import get_logger
from warden.mandate.extractor import MandateExtractor
from warden.policy.evaluator import LoadedPolicy, load_policy
from warden.secrets import read_token_secret
from warden.simulate.simulator import ChainSimulator
from warden.storage.database import Database
from warden.storage.migrate import migrate

log = get_logger(__name__)


class Services:
    def __init__(self, settings: Settings, clock: Clock | None = None) -> None:
        self.settings = settings
        self.clock = clock or SystemClock()
        self.db = Database(settings.db_path)
        self.store = FirewallStore(self.db)
        self.limiters = LimiterRegistry()
        self.queue = JobQueue(self.db)
        self.handlers: dict[str, Handler] = {}
        self.worker: Worker | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self.http = httpx.AsyncClient(timeout=30.0)
        self.rpc = RpcClient(settings.rpc_url)
        self.world: World | None = None
        self.registries = Registries()
        self.policy: LoadedPolicy | None = None
        self.firewall: Firewall | None = None
        self.extractor: MandateExtractor | None = None
        self.dry_run_hashes: set[str] = set()
        self.firewall_error: str | None = None

    def _model(self, spec: str) -> ChatModel | None:
        try:
            return build_chat_model(spec, self.settings, self.limiters)
        except ProviderUnavailable as exc:
            log.warning("llm.unavailable", spec=spec, error=str(exc))
            return None

    def build_firewall(self) -> None:
        """(Re)build the firewall from the current policy file and deployment record."""
        try:
            self.policy = load_policy(self.settings.policy_path.read_text(encoding="utf-8"))
            self.world = load_world("anvil") if deployment_path("anvil").exists() else None
            if self.world is None:
                raise FileNotFoundError(
                    "contracts/deployments/anvil.json (run warden chain deploy)"
                )
            self.registries = Registries.from_world(self.world)
            secret = read_token_secret(self.settings.secrets_dir)
        except (OSError, ValueError) as exc:
            self.firewall_error = f"{type(exc).__name__}: {exc}"
            log.warning("firewall.unavailable", error=self.firewall_error)
            return
        judge_model = self._model(self.settings.judge_model)
        self.firewall = Firewall(
            store=self.store,
            policy=self.policy,
            registries=self.registries,
            clock=self.clock,
            token_secret=secret,
            simulator=ChainSimulator(self.rpc),
            history=HistoryIndex(self.rpc, self.world.user, self.registries),
            judge=IntentJudge(judge_model) if judge_model else None,
            config=CONFIGS["D5"],
        )
        extractor_model = self._model(self.settings.extractor_model)
        self.extractor = (
            MandateExtractor(extractor_model, self.registries) if extractor_model else None
        )
        self.firewall_error = None

    async def start(self, *, run_worker: bool = True) -> None:
        await self.db.open()
        await migrate(self.db, "warden")
        self.build_firewall()
        if run_worker:
            self.worker = Worker(self.queue, self.handlers, self.limiters)
            self._tasks.append(asyncio.create_task(self.worker.run_forever()))
            self._tasks.append(asyncio.create_task(self._expire_loop()))

    async def _expire_loop(self) -> None:
        while True:
            await asyncio.sleep(5)
            if self.firewall is not None:
                try:
                    await self.firewall.expire_approvals()
                except Exception as exc:
                    log.error("approvals.expire_failed", error=str(exc))

    async def stop(self) -> None:
        if self.worker is not None:
            self.worker.stop()
        for task in self._tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self.http.aclose()
        await self.rpc.aclose()
        await self.db.close()

    async def _probe(self, url: str, payload: dict[str, Any] | None = None) -> bool:
        try:
            if payload is None:
                r = await self.http.get(url, timeout=2.0)
            else:
                r = await self.http.post(url, json=payload, timeout=2.0)
            return r.status_code < 500
        except httpx.HTTPError:
            return False

    async def readiness(self) -> dict[str, Any]:
        anvil = await self._probe(
            self.settings.rpc_url,
            {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
        )
        signer = await self._probe(f"{self.settings.signer_url}/health")
        return {
            "version": __version__,
            "anvil": anvil,
            "signer": signer,
            "firewall": self.firewall is not None,
            "firewall_error": self.firewall_error,
            "policy_sha256": self.policy.sha256 if self.policy else None,
            "extractor": self.extractor is not None,
            "queue": await self.queue.counts(),
            "pending_approvals": len(await self.store.list_approvals("pending")),
            "limiters": [asdict(lim.snapshot()) for lim in self.limiters.all()],
        }
