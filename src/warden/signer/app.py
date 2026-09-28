"""The signer's HTTP API (127.0.0.1:8201). Only the Warden API process calls it."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from warden.chain.rpc import RpcClient
from warden.chains import ALLOWED_CHAIN_IDS
from warden.clock import SystemClock
from warden.config import Settings, get_settings
from warden.firewall.models import Proposal
from warden.logging import configure_logging, get_logger
from warden.secrets import read_signer_key, read_token_secret
from warden.signer.core import Signer, SignerRefused
from warden.storage.database import Database
from warden.storage.migrate import migrate

log = get_logger(__name__)


class SignRequest(BaseModel):
    decision_token: str
    proposal: Proposal


def create_signer_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(settings.log_level, settings.log_json)
        db = await Database(settings.signer_db_path).open()
        await migrate(db, "signer")
        rpc = RpcClient(settings.rpc_url)
        app.state.signer = Signer(
            key=read_signer_key(settings.secrets_dir),
            token_secret=read_token_secret(settings.secrets_dir),
            db=db,
            rpc=rpc,
            clock=SystemClock(),
            max_native_wei=settings.signer_max_native_wei,
            max_token_amount=settings.signer_max_token_amount,
        )
        try:
            yield
        finally:
            await rpc.aclose()
            await db.close()

    app = FastAPI(title="Warden signer", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        signer: Signer = app.state.signer
        return {"status": "ok", "chain_ids": sorted(ALLOWED_CHAIN_IDS), "address": signer.address}

    @app.post("/sign")
    async def sign(req: SignRequest) -> JSONResponse:
        signer: Signer = app.state.signer
        try:
            result = await signer.sign(req.decision_token, req.proposal)
        except SignerRefused as exc:
            log.warning("signer.refused", reason=exc.reason)
            return JSONResponse(
                {"error": "signer_refused", "reason": exc.reason, "detail": str(exc)},
                status_code=403,
            )
        return JSONResponse(asdict(result))

    @app.get("/signatures/{decision_id}")
    async def signature(decision_id: str) -> dict[str, Any]:
        signer: Signer = app.state.signer
        row = await signer.signature_for(decision_id)
        if row is None:
            raise HTTPException(404, "no signature for this decision")
        return row

    return app
