"""Structured JSON logging with trace-id injection and secret redaction.

Never logged: private keys, the decision-token secret, decision tokens, signatures, signed payloads,
API keys. The redaction processor below is a safety net; code should not pass these values to the
logger in the first place. ``tests/unit/test_logging.py`` scans real output for them.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog
from opentelemetry import trace

_SECRET_KEYS = re.compile(
    r"(api[_-]?key|secret|token|private[_-]?key|signature|password|authorization|raw_tx|signed)",
    re.IGNORECASE,
)
_SECRET_VALUES = [
    re.compile(r"wdt1\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # decision tokens
    re.compile(r"\b(?:0x)?[0-9a-fA-F]{64}\b"),  # private keys / 32-byte secrets
    re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),  # Groq API keys
]
# Hashes are 64 hex chars too; fields named like hashes are allowed through.
_HASH_KEYS = re.compile(r"(sha256|hash|_id$|^id$|trace|span)", re.IGNORECASE)

REDACTED = "[redacted]"


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        for pattern in _SECRET_VALUES:
            value = pattern.sub(REDACTED, value)
        return value
    if isinstance(value, dict):
        return {k: _redact_item(k, v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_redact_value(v) for v in value]
    return value


def _redact_item(key: str, value: Any) -> Any:
    if _HASH_KEYS.search(key):
        return value
    if _SECRET_KEYS.search(key):
        return REDACTED
    return _redact_value(value)


def redact_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key in list(event_dict.keys()):
        event_dict[key] = _redact_item(key, event_dict[key])
    return event_dict


def trace_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    ctx = trace.get_current_span().get_span_context()
    if ctx.is_valid:
        event_dict["trace_id"] = format(ctx.trace_id, "032x")
        event_dict["span_id"] = format(ctx.span_id, "016x")
    return event_dict


class _StderrProxy:
    """Resolve ``sys.stderr`` on every write, so a replaced or closed stream never breaks logging."""

    def write(self, text: str) -> int:
        return sys.stderr.write(text)

    def flush(self) -> None:
        sys.stderr.flush()


def configure_logging(level: str = "INFO", json: bool = True) -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level.upper())
    renderer: Any = structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            trace_processor,
            redact_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[level.upper()]
        ),
        logger_factory=structlog.PrintLoggerFactory(file=_StderrProxy()),  # type: ignore[arg-type]
        cache_logger_on_first_use=False,
    )


def get_logger(name: str | None = None) -> Any:
    return structlog.get_logger(name)
