"""Liveness and readiness."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from warden.services import Services

router = APIRouter(tags=["ops"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
async def ready(request: Request) -> dict[str, Any]:
    services: Services = request.app.state.services
    return await services.readiness()
