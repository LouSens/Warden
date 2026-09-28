"""Composition root: builds and owns every long-lived component of the API process."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any

import httpx

from warden import __version__
from warden.config import Settings
from warden.jobs.queue import JobQueue
from warden.jobs.worker import Handler, Worker
from warden.llm.ratelimit import LimiterRegistry
from warden.storage.database import Database
from warden.storage.migrate import migrate


class Services:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = Database(settings.db_path)
        self.limiters = LimiterRegistry()
        self.queue = JobQueue(self.db)
        self.handlers: dict[str, Handler] = {}
        self.worker: Worker | None = None
        self._worker_task: asyncio.Task[None] | None = None
        self.http = httpx.AsyncClient(timeout=10.0)

    async def start(self, *, run_worker: bool = True) -> None:
        await self.db.open()
        await migrate(self.db, "warden")
        if run_worker:
            self.worker = Worker(self.queue, self.handlers, self.limiters)
            self._worker_task = asyncio.create_task(self.worker.run_forever())

    async def stop(self) -> None:
        if self.worker is not None:
            self.worker.stop()
        if self._worker_task is not None:
            await self._worker_task
        await self.http.aclose()
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
        jobs = await self.queue.counts()
        return {
            "version": __version__,
            "anvil": anvil,
            "signer": signer,
            "queue": jobs,
            "limiters": [asdict(lim.snapshot()) for lim in self.limiters.all()],
        }
