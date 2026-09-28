"""A scripted ChatModel for tests and harness dry-runs (no network, no tokens)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from warden.llm.base import Completion, Message, ToolCall, ToolSpec, Usage

Responder = Callable[[list[Message], list[ToolSpec] | None], Completion | str]


@dataclass
class FakeCall:
    messages: list[Message]
    tools: list[ToolSpec] | None
    temperature: float
    json_mode: bool


@dataclass
class FakeChatModel:
    """Returns scripted replies in order, or asks ``responder`` for each reply."""

    replies: list[Completion | str] = field(default_factory=list)
    responder: Responder | None = None
    name: str = "fake:model"
    calls: list[FakeCall] = field(default_factory=list)

    @property
    def model(self) -> str:
        return self.name

    async def complete(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> Completion:
        self.calls.append(FakeCall(list(messages), tools, temperature, json_mode))
        if self.responder is not None:
            reply = self.responder(messages, tools)
        elif self.replies:
            reply = self.replies.pop(0)
        else:
            raise AssertionError("FakeChatModel ran out of scripted replies")
        if isinstance(reply, str):
            tokens_in = sum(len(m.content) for m in messages) // 4
            return Completion(reply, self.name, Usage(tokens_in, len(reply) // 4))
        return reply


def tool_reply(name: str, arguments: dict[str, object], call_id: str = "call_1") -> Completion:
    """A completion that calls one tool."""
    return Completion(
        "", "fake:model", Usage(10, 5), tool_calls=(ToolCall(call_id, name, dict(arguments)),)
    )
