"""OpenAI-compatible chat completions client, used for Groq and for Ollama's ``/v1`` endpoint."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from warden.llm.base import (
    Completion,
    LLMError,
    Message,
    ProviderUnavailable,
    RateLimitExceeded,
    Role,
    ToolCall,
    ToolSpec,
    Usage,
)
from warden.llm.ratelimit import RateLimiter, parse_duration_s


def estimate_tokens(messages: list[Message], tools: list[ToolSpec] | None, max_tokens: int) -> int:
    """Cheap upper-ish estimate (4 chars per token) used only for client-side pacing."""
    chars = sum(
        len(m.content) + sum(len(json.dumps(c.arguments)) for c in m.tool_calls) for m in messages
    )
    if tools:
        chars += sum(len(json.dumps(t.parameters)) + len(t.description) for t in tools)
    return chars // 4 + max_tokens


def _message_to_wire(m: Message) -> dict[str, Any]:
    wire: dict[str, Any] = {"role": m.role.value, "content": m.content}
    if m.role is Role.ASSISTANT and m.tool_calls:
        wire["tool_calls"] = [
            {
                "id": c.id,
                "type": "function",
                "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
            }
            for c in m.tool_calls
        ]
    if m.role is Role.TOOL:
        wire["tool_call_id"] = m.tool_call_id
        if m.name:
            wire["name"] = m.name
    return wire


def _parse_tool_calls(raw: list[dict[str, Any]] | None) -> tuple[ToolCall, ...]:
    calls = []
    for i, c in enumerate(raw or []):
        fn = c.get("function", {})
        args_raw = fn.get("arguments") or "{}"
        try:
            args = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
        except json.JSONDecodeError:
            args = {"_unparsed": args_raw}
        if not isinstance(args, dict):
            args = {"_value": args}
        calls.append(
            ToolCall(id=c.get("id") or f"call_{i}", name=fn.get("name", ""), arguments=args)
        )
    return tuple(calls)


class OpenAICompatChat:
    """One model behind an OpenAI-compatible ``/chat/completions`` endpoint."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key: str | None = None,
        provider: str = "openai-compatible",
        limiter: RateLimiter | None = None,
        client: httpx.AsyncClient | None = None,
        timeout_s: float = 60.0,
        max_retries: int = 2,
    ) -> None:
        self._model = model
        self.provider = provider
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.limiter = limiter
        self._client = client or httpx.AsyncClient(timeout=timeout_s)
        self._max_retries = max_retries

    @property
    def model(self) -> str:
        return self._model

    async def aclose(self) -> None:
        await self._client.aclose()

    async def complete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> Completion:
        body: dict[str, Any] = {
            "model": self._model,
            "messages": [_message_to_wire(m) for m in messages],
            "temperature": temperature,
        }
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]
            body["tool_choice"] = "auto"
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        estimate = estimate_tokens(messages, tools, max_tokens or 1024)
        if self.limiter is not None:
            if self.limiter.is_open():
                raise RateLimitExceeded(self._model, self.limiter.retry_after_s())
            await self.limiter.acquire(estimate)

        attempt = 0
        while True:
            try:
                resp = await self._client.post(
                    f"{self._base_url}/chat/completions", json=body, headers=headers
                )
            except httpx.HTTPError as exc:
                if attempt < self._max_retries:
                    attempt += 1
                    await asyncio.sleep(0.5 * 2**attempt)
                    continue
                raise ProviderUnavailable(f"{self.provider}: {type(exc).__name__}") from exc

            if self.limiter is not None:
                self.limiter.observe_headers(resp.headers)
            if resp.status_code == 429:
                retry = parse_duration_s(resp.headers.get("retry-after", "") or "")
                if self.limiter is not None:
                    self.limiter.trip(retry)
                raise RateLimitExceeded(self._model, retry)
            if resp.status_code >= 500 and attempt < self._max_retries:
                attempt += 1
                await asyncio.sleep(0.5 * 2**attempt)
                continue
            if resp.status_code >= 500:
                raise ProviderUnavailable(f"{self.provider}: HTTP {resp.status_code}")
            if resp.status_code >= 400:
                raise LLMError(f"{self.provider}: HTTP {resp.status_code}: {resp.text[:300]}")
            break

        data = resp.json()
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        usage_raw = data.get("usage") or {}
        usage = Usage(
            input_tokens=int(usage_raw.get("prompt_tokens", 0)),
            output_tokens=int(usage_raw.get("completion_tokens", 0)),
        )
        if self.limiter is not None:
            self.limiter.record_actual(estimate, usage.total or estimate)
        return Completion(
            content=msg.get("content") or "",
            model=data.get("model", self._model),
            usage=usage,
            tool_calls=_parse_tool_calls(msg.get("tool_calls")),
            finish_reason=choice.get("finish_reason"),
        )
