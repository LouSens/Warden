"""The provider-neutral chat interface every LLM role in Warden uses."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None
    name: str | None = None

    @staticmethod
    def system(content: str) -> Message:
        return Message(Role.SYSTEM, content)

    @staticmethod
    def user(content: str) -> Message:
        return Message(Role.USER, content)

    @staticmethod
    def assistant(content: str, tool_calls: tuple[ToolCall, ...] = ()) -> Message:
        return Message(Role.ASSISTANT, content, tool_calls=tool_calls)

    @staticmethod
    def tool(tool_call_id: str, name: str, content: str) -> Message:
        return Message(Role.TOOL, content, tool_call_id=tool_call_id, name=name)


@dataclass(frozen=True)
class ToolSpec:
    """A tool the model may call, with a JSON-schema ``parameters`` object."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            self.input_tokens + other.input_tokens, self.output_tokens + other.output_tokens
        )


@dataclass(frozen=True)
class Completion:
    content: str
    model: str
    usage: Usage = field(default_factory=Usage)
    tool_calls: tuple[ToolCall, ...] = ()
    finish_reason: str | None = None
    cached: bool = False


class LLMError(RuntimeError):
    """Base class for provider failures."""


class RateLimitExceeded(LLMError):
    def __init__(self, model: str, retry_after_s: float | None) -> None:
        super().__init__(f"rate limit exceeded for {model}; retry after {retry_after_s}s")
        self.model = model
        self.retry_after_s = retry_after_s


class ProviderUnavailable(LLMError):
    """Network failure, 5xx, or a provider that is not configured."""


class ChatModel(Protocol):
    """One model at one provider. Implementations must be safe to call concurrently."""

    @property
    def model(self) -> str: ...

    async def complete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> Completion: ...
