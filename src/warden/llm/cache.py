"""Disk cache for deterministic LLM calls.

Only calls at temperature 0 are cached: extraction, guard and judge calls repeat across defences and
replays, and caching them makes repeats free. Sampled agent calls (temperature > 0) are never cached,
because pass^k needs independent samples.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from warden.canonical import canonical_sha256
from warden.llm.base import ChatModel, Completion, Message, ToolCall, ToolSpec, Usage


def _key(
    model: str,
    messages: list[Message],
    tools: list[ToolSpec] | None,
    max_tokens: int | None,
    json_mode: bool,
) -> str:
    return canonical_sha256(
        {
            "model": model,
            "messages": [
                {
                    "role": m.role.value,
                    "content": m.content,
                    "tool_calls": [asdict(c) for c in m.tool_calls],
                    "tool_call_id": m.tool_call_id,
                }
                for m in messages
            ],
            "tools": [asdict(t) for t in tools or []],
            "max_tokens": max_tokens,
            "json_mode": json_mode,
        }
    )


class CachingChatModel:
    def __init__(self, inner: ChatModel, cache_dir: Path) -> None:
        self._inner = inner
        self._dir = cache_dir
        self.hits = 0
        self.misses = 0

    @property
    def model(self) -> str:
        return self._inner.model

    def _path(self, key: str) -> Path:
        return self._dir / key[:2] / f"{key}.json"

    async def complete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> Completion:
        if temperature != 0.0:
            return await self._inner.complete(
                messages,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                json_mode=json_mode,
            )
        key = _key(self.model, messages, tools, max_tokens, json_mode)
        path = self._path(key)
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self.hits += 1
            return Completion(
                content=data["content"],
                model=data["model"],
                usage=Usage(**data["usage"]),
                tool_calls=tuple(ToolCall(**c) for c in data["tool_calls"]),
                finish_reason=data.get("finish_reason"),
                cached=True,
            )
        self.misses += 1
        result = await self._inner.complete(
            messages,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "content": result.content,
                    "model": result.model,
                    "usage": asdict(result.usage),
                    "tool_calls": [asdict(c) for c in result.tool_calls],
                    "finish_reason": result.finish_reason,
                }
            ),
            encoding="utf-8",
        )
        tmp.replace(path)
        return result
