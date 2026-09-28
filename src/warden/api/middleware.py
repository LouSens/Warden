"""Request ids and the local-only guard."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from warden.api.errors import WardenError
from warden.ids import new_id

LOOPBACK = {"127.0.0.1", "::1", "localhost", "testclient"}


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        rid = request.headers.get("x-request-id") or new_id("req")
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response


def require_local(request: Request) -> None:
    """Dependency for endpoints that change policy or the address book."""
    host = request.client.host if request.client else ""
    if host not in LOOPBACK:
        raise WardenError(
            "this endpoint is available on the local machine only",
            code="local_only",
            status_code=403,
        )
