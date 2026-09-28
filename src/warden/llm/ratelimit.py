"""Per-model rate limiting and the rate-limit circuit breaker.

Two sources of truth are combined:

* a client-side budget for requests and tokens per minute, so Warden does not hit the limit;
* the provider's own ``x-ratelimit-*`` headers, which say what is really left (including the daily
  token budget that is the binding limit on the Groq free tier).

When the provider says a model is exhausted, or answers 429, the breaker opens for that model until
the reset time. The job queue asks :meth:`RateLimiter.is_open` before leasing that model's work.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass

_DURATION = re.compile(
    r"(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m(?!s))?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?$"
)


def parse_duration_s(text: str) -> float | None:
    """Parse Groq-style durations such as ``"2m59.56s"``, ``"7.66s"``, ``"1h2m"``, ``"250ms"``."""
    text = text.strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    m = _DURATION.fullmatch(text)
    if not m or not any(m.groups()):
        return None
    h, mi, s, ms = (float(g) if g else 0.0 for g in m.groups())
    return h * 3600 + mi * 60 + s + ms / 1000


@dataclass
class LimiterSnapshot:
    model: str
    remaining_requests: int | None
    remaining_tokens: int | None
    reset_requests_s: float | None
    reset_tokens_s: float | None
    open_until: float | None
    retry_after_s: float | None


class RateLimiter:
    """Budget for one model. ``rpm``/``tpm`` are client-side ceilings (use the free-tier values)."""

    def __init__(
        self,
        model: str,
        rpm: int = 30,
        tpm: int = 8_000,
        min_tokens_headroom: int = 0,
    ) -> None:
        self.model = model
        self.rpm = rpm
        self.tpm = tpm
        self.min_tokens_headroom = min_tokens_headroom
        self._requests: deque[float] = deque()
        self._tokens: deque[tuple[float, int]] = deque()
        self._lock = asyncio.Lock()
        self.remaining_requests: int | None = None
        self.remaining_tokens: int | None = None
        self.reset_requests_s: float | None = None
        self.reset_tokens_s: float | None = None
        self.open_until: float | None = None

    # -------------------------------------------------------------- breaker
    def is_open(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if self.open_until is not None and now >= self.open_until:
            self.open_until = None
        return self.open_until is not None

    def trip(self, retry_after_s: float | None, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        delay = retry_after_s if retry_after_s and retry_after_s > 0 else 60.0
        until = now + delay
        self.open_until = max(self.open_until or 0.0, until)

    def retry_after_s(self, now: float | None = None) -> float | None:
        now = time.monotonic() if now is None else now
        if not self.is_open(now) or self.open_until is None:
            return None
        return round(self.open_until - now, 1)

    # -------------------------------------------------------------- headers
    def observe_headers(self, headers: Mapping[str, str], now: float | None = None) -> None:
        def _int(name: str) -> int | None:
            v = headers.get(name)
            try:
                return int(v) if v is not None else None
            except ValueError:
                return None

        rr = _int("x-ratelimit-remaining-requests")
        rt = _int("x-ratelimit-remaining-tokens")
        if rr is not None:
            self.remaining_requests = rr
        if rt is not None:
            self.remaining_tokens = rt
        reset_r = headers.get("x-ratelimit-reset-requests")
        reset_t = headers.get("x-ratelimit-reset-tokens")
        self.reset_requests_s = parse_duration_s(reset_r) if reset_r else self.reset_requests_s
        self.reset_tokens_s = parse_duration_s(reset_t) if reset_t else self.reset_tokens_s
        if rr == 0:
            self.trip(self.reset_requests_s, now)
        retry_after = headers.get("retry-after")
        if retry_after:
            self.trip(parse_duration_s(retry_after), now)

    # -------------------------------------------------------------- client budget
    def _prune(self, now: float) -> None:
        while self._requests and now - self._requests[0] >= 60:
            self._requests.popleft()
        while self._tokens and now - self._tokens[0][0] >= 60:
            self._tokens.popleft()

    def _wait_needed(self, estimated_tokens: int, now: float) -> float:
        self._prune(now)
        waits = [0.0]
        if len(self._requests) >= self.rpm:
            waits.append(60 - (now - self._requests[0]))
        used = sum(t for _, t in self._tokens)
        if self._tokens and used + estimated_tokens > self.tpm:
            waits.append(60 - (now - self._tokens[0][0]))
        return max(waits)

    async def acquire(self, estimated_tokens: int) -> None:
        """Wait until a call of about ``estimated_tokens`` fits in the per-minute budget."""
        async with self._lock:
            while True:
                now = time.monotonic()
                wait = self._wait_needed(estimated_tokens, now)
                if wait <= 0:
                    self._requests.append(now)
                    self._tokens.append((now, estimated_tokens))
                    return
                await asyncio.sleep(min(wait, 5.0))

    def record_actual(self, estimated_tokens: int, actual_tokens: int) -> None:
        """Replace the most recent estimate with the real token count."""
        for i in range(len(self._tokens) - 1, -1, -1):
            ts, t = self._tokens[i]
            if t == estimated_tokens:
                self._tokens[i] = (ts, actual_tokens)
                return

    def snapshot(self) -> LimiterSnapshot:
        return LimiterSnapshot(
            model=self.model,
            remaining_requests=self.remaining_requests,
            remaining_tokens=self.remaining_tokens,
            reset_requests_s=self.reset_requests_s,
            reset_tokens_s=self.reset_tokens_s,
            open_until=self.open_until,
            retry_after_s=self.retry_after_s(),
        )


class LimiterRegistry:
    """One limiter per model, shared by every caller in the process."""

    def __init__(self) -> None:
        self._limiters: dict[str, RateLimiter] = {}

    def get(self, model: str, rpm: int = 30, tpm: int = 8_000) -> RateLimiter:
        if model not in self._limiters:
            self._limiters[model] = RateLimiter(model, rpm=rpm, tpm=tpm)
        return self._limiters[model]

    def all(self) -> list[RateLimiter]:
        return list(self._limiters.values())

    def open_models(self) -> set[str]:
        return {m for m, lim in self._limiters.items() if lim.is_open()}
