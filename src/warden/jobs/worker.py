"""The job worker: leases jobs, dispatches them by kind, and respects the rate-limit breaker."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Any

from warden.jobs.queue import Job, JobQueue
from warden.llm.base import RateLimitExceeded
from warden.llm.ratelimit import LimiterRegistry
from warden.logging import get_logger

Handler = Callable[[Job], Awaitable[dict[str, Any] | None]]

log = get_logger(__name__)


class Worker:
    def __init__(
        self,
        queue: JobQueue,
        handlers: dict[str, Handler],
        limiters: LimiterRegistry | None = None,
        poll_s: float = 1.0,
    ) -> None:
        self.queue = queue
        self.handlers = handlers
        self.limiters = limiters
        self.poll_s = poll_s
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def run_once(self) -> bool:
        """Process at most one job. Returns True if a job was processed."""
        paused = self.limiters.open_models() if self.limiters else set()
        job = await self.queue.lease(exclude_lanes=paused)
        if job is None:
            return False
        handler = self.handlers.get(job.kind)
        if handler is None:
            await self.queue.fail(job.id, f"no handler for kind {job.kind!r}")
            return True
        try:
            result = await handler(job)
        except RateLimitExceeded as exc:
            log.warning("job.paused", job_id=job.id, lane=job.lane, retry_after_s=exc.retry_after_s)
            await self.queue.fail(
                job.id, str(exc), retry_after_s=exc.retry_after_s or 60.0, count_attempt=False
            )
        except Exception as exc:
            state = await self.queue.fail(job.id, f"{type(exc).__name__}: {exc}")
            log.error("job.failed", job_id=job.id, kind=job.kind, state=state, error=str(exc))
        else:
            await self.queue.complete(job.id, result)
        return True

    async def run_forever(self) -> None:
        while not self._stop.is_set():
            worked = await self.run_once()
            if not worked:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), timeout=self.poll_s)
