"""OpenTelemetry setup: JSONL file exporter always on, OTLP optional."""

from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

_configured = False


class JsonlSpanExporter(SpanExporter):
    """Writes one JSON object per span to ``<dir>/YYYY-MM-DD.jsonl``."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._lock = threading.Lock()

    def _path(self) -> Path:
        return self.directory / f"{datetime.now(UTC):%Y-%m-%d}.jsonl"

    @staticmethod
    def span_to_dict(span: ReadableSpan) -> dict[str, Any]:
        ctx = span.get_span_context()
        parent = span.parent
        return {
            "trace_id": format(ctx.trace_id, "032x") if ctx else None,
            "span_id": format(ctx.span_id, "016x") if ctx else None,
            "parent_span_id": format(parent.span_id, "016x") if parent else None,
            "name": span.name,
            "start_ns": span.start_time,
            "end_ns": span.end_time,
            "duration_ms": (
                round((span.end_time - span.start_time) / 1e6, 3)
                if span.end_time and span.start_time
                else None
            ),
            "status": span.status.status_code.name,
            "attributes": {
                k: v if isinstance(v, str | int | float | bool) else list(v)
                for k, v in (span.attributes or {}).items()
            },
            "events": [
                {"name": e.name, "attributes": dict(e.attributes or {})} for e in span.events
            ],
        }

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.directory.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(self.span_to_dict(s), default=str) for s in spans]
        with self._lock, self._path().open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def configure_tracing(
    traces_dir: Path,
    service_name: str = "warden",
    otlp_endpoint: str | None = None,
    synchronous: bool = False,
) -> TracerProvider:
    """Install a global tracer provider. Safe to call more than once (later calls are no-ops)."""
    global _configured
    provider = trace.get_tracer_provider()
    if _configured and isinstance(provider, TracerProvider):
        return provider
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    exporter = JsonlSpanExporter(traces_dir)
    provider.add_span_processor(
        SimpleSpanProcessor(exporter) if synchronous else BatchSpanProcessor(exporter)
    )
    if otlp_endpoint:
        # Imported lazily: the OTLP exporter is an optional dependency.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore[import-not-found]
            OTLPSpanExporter,
        )

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
    trace.set_tracer_provider(provider)
    _configured = True
    return provider


def get_tracer(name: str = "warden") -> trace.Tracer:
    return trace.get_tracer(name)
