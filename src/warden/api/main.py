"""FastAPI app factory. Run with ``uvicorn warden.api.main:app --port 8200``."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from warden import __version__
from warden.api.errors import install_error_handlers
from warden.api.middleware import RequestIdMiddleware
from warden.api.routers import health
from warden.config import Settings, get_settings
from warden.logging import configure_logging
from warden.services import Services
from warden.tracing import configure_tracing


def create_app(settings: Settings | None = None, *, run_worker: bool = True) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(settings.log_level, settings.log_json)
        configure_tracing(settings.traces_dir, otlp_endpoint=settings.otlp_endpoint)
        services = Services(settings)
        await services.start(run_worker=run_worker)
        app.state.services = services
        try:
            yield
        finally:
            await services.stop()

    app = FastAPI(
        title="Warden",
        version=__version__,
        summary="Transaction firewall for LLM agents that hold wallets",
        lifespan=lifespan,
    )
    app.add_middleware(RequestIdMiddleware)
    install_error_handlers(app)
    app.include_router(health.router)
    return app


app = create_app()
