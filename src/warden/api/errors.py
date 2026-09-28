"""Error responses: ``{"error", "detail", "request_id"}`` for every failure."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ErrorResponse(BaseModel):
    error: str
    detail: str
    request_id: str | None = None


class WardenError(Exception):
    """An error with a stable machine-readable code (see docs/api.md §1.1)."""

    status_code = 400
    code = "invalid_request"

    def __init__(
        self,
        detail: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        self.headers = headers or {}


class NotFound(WardenError):
    status_code = 404
    code = "not_found"


class Conflict(WardenError):
    status_code = 409
    code = "idempotency_conflict"


def _rid(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(WardenError)
    async def _warden(request: Request, exc: WardenError) -> JSONResponse:
        body = ErrorResponse(error=exc.code, detail=exc.detail, request_id=_rid(request))
        return JSONResponse(body.model_dump(), status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        detail = "; ".join(
            f"{'.'.join(str(p) for p in e.get('loc', []))}: {e.get('msg')}" for e in exc.errors()
        )
        body = ErrorResponse(
            error="invalid_request", detail=detail[:2000], request_id=_rid(request)
        )
        return JSONResponse(body.model_dump(), status_code=400)
