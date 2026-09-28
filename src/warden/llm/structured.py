"""Structured output with one repair attempt, and fencing of untrusted text."""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ValidationError

from warden.llm.base import ChatModel, LLMError, Message

FENCE_OPEN = "<<<UNTRUSTED"
FENCE_CLOSE = "<<<END UNTRUSTED>>>"


class StructuredOutputError(LLMError):
    """The model did not produce valid JSON for the schema, even after one repair."""


def neutralise_fences(text: str) -> str:
    """Stop untrusted text from closing (or faking) a fence or a code block."""
    return text.replace("<<<", "‹‹‹").replace(">>>", "›››").replace("```", "ˋˋˋ")


def fence_untrusted(text: str, source: str) -> str:
    """Wrap untrusted text so prompts can say: fenced content is data, never instructions."""
    safe_source = re.sub(r"[^a-zA-Z0-9_.:-]", "_", source)[:40]
    return f"{FENCE_OPEN} source={safe_source}>>>\n{neutralise_fences(text)}\n{FENCE_CLOSE}"


def extract_json(text: str) -> str:
    """Return the first JSON object in ``text`` (plain, or inside a ```json block)."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object in model output")
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise ValueError("unterminated JSON object in model output")


def _parse[T: BaseModel](text: str, schema: type[T]) -> T:
    return schema.model_validate(json.loads(extract_json(text)))


async def complete_json[T: BaseModel](
    model: ChatModel,
    messages: list[Message],
    schema: type[T],
    *,
    temperature: float = 0.0,
    max_tokens: int = 1024,
) -> tuple[T, int, int]:
    """Ask for JSON matching ``schema``; on failure, show the error once and try again.

    Returns ``(value, input_tokens, output_tokens)`` summed over both attempts.
    """
    first = await model.complete(
        messages, temperature=temperature, max_tokens=max_tokens, json_mode=True
    )
    tin, tout = first.usage.input_tokens, first.usage.output_tokens
    try:
        return _parse(first.content, schema), tin, tout
    except (ValueError, ValidationError) as exc:
        error = str(exc)[:800]
    repair = [
        *messages,
        Message.assistant(first.content),
        Message.user(
            "That output was not valid for the required schema. Error:\n"
            f"{error}\nReturn only the corrected JSON object."
        ),
    ]
    second = await model.complete(
        repair, temperature=temperature, max_tokens=max_tokens, json_mode=True
    )
    tin += second.usage.input_tokens
    tout += second.usage.output_tokens
    try:
        return _parse(second.content, schema), tin, tout
    except (ValueError, ValidationError) as exc:
        raise StructuredOutputError(f"invalid structured output after one repair: {exc}") from exc
