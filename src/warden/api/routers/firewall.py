"""Firewall endpoints under /api/v1 (docs/api.md §2)."""

from __future__ import annotations

from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field

from warden.api.errors import Conflict, NotFound, WardenError
from warden.api.middleware import require_local
from warden.canonical import sha256_hex
from warden.chain.abi import checksum
from warden.chains import ChainNotAllowedError, require_allowed
from warden.firewall.dryrun import dry_run
from warden.firewall.models import Decision, Origin, Proposal, ProposalKind
from warden.firewall.pipeline import ApprovalResolved, Firewall, UnknownSession
from warden.llm.base import LLMError, RateLimitExceeded
from warden.mandate.extractor import TrustedPrompt
from warden.mandate.schema import Mandate
from warden.policy.evaluator import PolicyInvalid, load_policy
from warden.services import Services

router = APIRouter(prefix="/api/v1", tags=["firewall"])


def services(request: Request) -> Services:
    svc: Services = request.app.state.services
    return svc


def firewall(svc: Services = Depends(services)) -> Firewall:
    if svc.firewall is None:
        raise WardenError(
            f"firewall not ready: {svc.firewall_error}",
            code="firewall_unavailable",
            status_code=503,
        )
    return svc.firewall


# ---------------------------------------------------------------- mandates / sessions


class MandateRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    ttl_s: int = Field(default=3600, ge=60, le=86400)


class MandateResponse(BaseModel):
    id: str
    mandate: Mandate
    body_sha256: str
    extractor_model: str | None = None
    prompt_version: str | None = None


@router.post("/mandates", response_model=MandateResponse)
async def create_mandate(
    req: MandateRequest,
    svc: Services = Depends(services),
    fw: Firewall = Depends(firewall),
) -> MandateResponse:
    if svc.extractor is None:
        raise WardenError(
            "no extractor model configured (set GROQ_API_KEY)",
            code="mandate_extraction_failed",
            status_code=422,
        )
    try:
        ex = await svc.extractor.extract(
            TrustedPrompt(req.prompt),
            book=await svc.store.book(svc.settings.chain_id),
            chain_id=svc.settings.chain_id,
            now=svc.clock.now(),
            ttl_s=req.ttl_s,
        )
    except RateLimitExceeded as exc:
        raise WardenError(
            str(exc),
            code="rate_limited",
            status_code=503,
            headers={"Retry-After": str(int(exc.retry_after_s or 60))},
        ) from exc
    except LLMError as exc:
        raise WardenError(str(exc), code="mandate_extraction_failed", status_code=422) from exc
    mid = await svc.store.insert_mandate(
        ex.mandate,
        prompt_sha256=ex.prompt_sha256,
        now=svc.clock.now(),
        extractor_model=ex.model,
        prompt_version=ex.prompt_version,
    )
    return MandateResponse(
        id=mid,
        mandate=ex.mandate,
        body_sha256=ex.mandate.sha256,
        extractor_model=ex.model,
        prompt_version=ex.prompt_version,
    )


@router.post("/mandates:manual", response_model=MandateResponse)
async def create_manual_mandate(
    mandate: Mandate, svc: Services = Depends(services)
) -> MandateResponse:
    mid = await svc.store.insert_mandate(mandate, prompt_sha256=sha256_hex(""), now=svc.clock.now())
    return MandateResponse(id=mid, mandate=mandate, body_sha256=mandate.sha256)


@router.get("/mandates/{mandate_id}", response_model=MandateResponse)
async def get_mandate(mandate_id: str, svc: Services = Depends(services)) -> MandateResponse:
    got = await svc.store.get_mandate(mandate_id)
    if got is None:
        raise NotFound(f"mandate {mandate_id}")
    m, row = got
    return MandateResponse(
        id=mandate_id,
        mandate=m,
        body_sha256=row["body_sha256"],
        extractor_model=row["extractor_model"],
        prompt_version=row["prompt_version"],
    )


class SessionRequest(BaseModel):
    mandate_id: str


@router.post("/sessions")
async def create_session(req: SessionRequest, svc: Services = Depends(services)) -> dict[str, Any]:
    if await svc.store.get_mandate(req.mandate_id) is None:
        raise NotFound(f"mandate {req.mandate_id}")
    sid = await svc.store.create_session(req.mandate_id, svc.clock.now())
    return {"id": sid, "mandate_id": req.mandate_id}


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, svc: Services = Depends(services)) -> dict[str, Any]:
    s = await svc.store.get_session(session_id)
    if s is None:
        raise NotFound(f"session {session_id}")
    got = await svc.store.get_mandate(s["mandate_id"])
    assert got is not None
    mandate = got[0]
    spent = await svc.store.spent(session_id)
    caps = []
    for asset, cap in mandate.session_cap.items():
        used = spent.get(asset.lower(), 0)
        caps.append(
            {
                "asset": asset,
                "symbol": svc.registries.symbol(asset),
                "spent": str(used),
                "cap": str(cap),
                "remaining": str(max(cap - used, 0)),
            }
        )
    return {
        "id": session_id,
        "mandate_id": s["mandate_id"],
        "created_at": s["created_at"],
        "caps": caps,
    }


# ---------------------------------------------------------------- proposals / decisions


class ProposalRequest(BaseModel):
    session_id: str
    kind: ProposalKind
    payload: dict[str, Any]
    origin: Literal["agent", "api"] = "api"  # "mcp" is set by the MCP server only
    chain_id: int | None = None


@router.post("/proposals", response_model=Decision)
async def create_proposal(
    req: ProposalRequest,
    svc: Services = Depends(services),
    fw: Firewall = Depends(firewall),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> Decision:
    chain_id = req.chain_id or int(req.payload.get("chain_id", svc.settings.chain_id))
    try:
        require_allowed(chain_id)
    except ChainNotAllowedError as exc:
        raise WardenError(str(exc), code="unsupported_chain") from exc
    proposal = Proposal(kind=req.kind, chain_id=chain_id, payload=req.payload)
    if idempotency_key:
        existing = await svc.store.find_by_idempotency_key(idempotency_key)
        if existing is not None:
            record = await svc.store.proposal_record(existing)
            assert record is not None
            if record["proposal"]["raw_sha256"] != sha256_hex_of(proposal):
                raise Conflict("same Idempotency-Key, different proposal")
            return await _decision_from_record(existing, svc)
    try:
        return await fw.evaluate(
            req.session_id, proposal, origin=Origin(req.origin), idempotency_key=idempotency_key
        )
    except UnknownSession as exc:
        raise NotFound(f"session {req.session_id}") from exc


def sha256_hex_of(proposal: Proposal) -> str:
    from warden.canonical import canonical_sha256

    return canonical_sha256(proposal.model_dump(mode="json"))


async def _decision_from_record(proposal_id: str, svc: Services) -> Decision:
    """Replay of an idempotent request: the recorded decision, without re-minting a token."""
    record = await svc.store.proposal_record(proposal_id)
    latest = await svc.store.latest_decision(proposal_id)
    assert record is not None and latest is not None
    from warden.firewall.models import Action, Effects, Finding

    return Decision(
        proposal_id=proposal_id,
        decision_id=latest.id,
        verdict=latest.verdict,
        decided_by=latest.decided_by,
        matched_rules=latest.matched_rules,
        reasons=latest.reasons,
        action=Action.model_validate(record["action"]),
        effects=Effects.model_validate(record["effects"]) if record["effects"] else None,
        findings=[Finding.model_validate(f) for f in record["findings"]],
        mandate_satisfied=False,
        policy_sha256=latest.policy_sha256,
        mandate_sha256=latest.mandate_sha256,
    )


@router.get("/proposals/{proposal_id}")
async def get_proposal(proposal_id: str, svc: Services = Depends(services)) -> dict[str, Any]:
    record = await svc.store.proposal_record(proposal_id)
    if record is None:
        raise NotFound(f"proposal {proposal_id}")
    return record


@router.get("/decisions")
async def list_decisions(
    verdict: str | None = None,
    since: str | None = None,
    session_id: str | None = None,
    limit: int = 100,
    svc: Services = Depends(services),
) -> list[dict[str, Any]]:
    return await svc.store.list_decisions(
        verdict=verdict, since=since, session_id=session_id, limit=min(limit, 500)
    )


# ---------------------------------------------------------------- approvals


class ApprovalAction(BaseModel):
    note: str | None = None


@router.get("/approvals")
async def list_approvals(
    state: str | None = "pending", svc: Services = Depends(services)
) -> list[dict[str, Any]]:
    return await svc.store.list_approvals(state)


async def _resolve(approval_id: str, approve: bool, body: ApprovalAction, fw: Firewall) -> Decision:
    try:
        return await fw.resolve_approval(approval_id, approve=approve, note=body.note)
    except KeyError as exc:
        raise NotFound(f"approval {approval_id}") from exc
    except ApprovalResolved as exc:
        raise WardenError(
            "approval is no longer pending", code="approval_resolved", status_code=409
        ) from exc


@router.post("/approvals/{approval_id}:approve", response_model=Decision)
async def approve(
    approval_id: str, body: ApprovalAction | None = None, fw: Firewall = Depends(firewall)
) -> Decision:
    return await _resolve(approval_id, True, body or ApprovalAction(), fw)


@router.post("/approvals/{approval_id}:deny", response_model=Decision)
async def deny(
    approval_id: str, body: ApprovalAction | None = None, fw: Firewall = Depends(firewall)
) -> Decision:
    return await _resolve(approval_id, False, body or ApprovalAction(), fw)


# ---------------------------------------------------------------- signing


class SignBody(BaseModel):
    decision_token: str
    proposal_id: str


@router.post("/sign")
async def sign(body: SignBody, svc: Services = Depends(services)) -> dict[str, Any]:
    record = await svc.store.proposal_record(body.proposal_id)
    if record is None:
        raise NotFound(f"proposal {body.proposal_id}")
    try:
        r = await svc.http.post(
            f"{svc.settings.signer_url}/sign",
            json={"decision_token": body.decision_token, "proposal": record["proposal"]["raw"]},
        )
    except httpx.HTTPError as exc:
        raise WardenError(
            "signer not reachable", code="signer_unavailable", status_code=503
        ) from exc
    data: dict[str, Any] = r.json()
    if r.status_code != 200:
        raise WardenError(
            f"signer refused: {data.get('reason')}", code="signer_refused", status_code=403
        )
    return data


# ---------------------------------------------------------------- policy


class PolicyBody(BaseModel):
    yaml: str


@router.get("/policy")
async def get_policy(svc: Services = Depends(services)) -> dict[str, Any]:
    if svc.policy is None:
        raise WardenError("no policy loaded", code="firewall_unavailable", status_code=503)
    return {"yaml": svc.policy.text, "sha256": svc.policy.sha256}


@router.post("/policy:validate")
async def validate_policy(body: PolicyBody) -> dict[str, Any]:
    try:
        loaded = load_policy(body.yaml)
    except PolicyInvalid as exc:
        return {"valid": False, "errors": exc.errors}
    return {"valid": True, "errors": [], "sha256": loaded.sha256}


@router.post("/policy:dry-run")
async def policy_dry_run(body: PolicyBody, svc: Services = Depends(services)) -> dict[str, Any]:
    try:
        loaded = load_policy(body.yaml)
    except PolicyInvalid as exc:
        raise WardenError("; ".join(exc.errors), code="policy_invalid", status_code=422) from exc
    report = await dry_run(svc.store, loaded, svc.registries)
    svc.dry_run_hashes.add(loaded.sha256)
    return report


@router.put("/policy", dependencies=[Depends(require_local)])
async def put_policy(body: PolicyBody, svc: Services = Depends(services)) -> dict[str, Any]:
    try:
        loaded = load_policy(body.yaml)
    except PolicyInvalid as exc:
        raise WardenError("; ".join(exc.errors), code="policy_invalid", status_code=422) from exc
    if loaded.sha256 not in svc.dry_run_hashes:
        raise WardenError(
            "run POST /policy:dry-run on this exact file first",
            code="dry_run_required",
            status_code=428,
        )
    svc.settings.policy_path.write_text(body.yaml, encoding="utf-8", newline="\n")
    svc.build_firewall()
    return {"sha256": loaded.sha256}


# ---------------------------------------------------------------- address book / audit


class BookBody(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    address: str
    chain_id: int | None = None


class BookPatch(BaseModel):
    label: str | None = None
    verified: bool | None = None


@router.get("/address-book")
async def list_book(
    chain_id: int | None = None, svc: Services = Depends(services)
) -> list[dict[str, Any]]:
    return [e.__dict__ for e in await svc.store.book(chain_id)]


@router.post("/address-book")
async def add_book(body: BookBody, svc: Services = Depends(services)) -> dict[str, Any]:
    try:
        address = checksum(body.address)
    except ValueError as exc:
        raise WardenError("invalid address") from exc
    chain_id = body.chain_id or svc.settings.chain_id
    bid = await svc.store.add_book_entry(
        body.label, address, chain_id, "user", True, svc.clock.now()
    )
    return {
        "id": bid,
        "label": body.label,
        "address": address,
        "chain_id": chain_id,
        "provenance": "user",
        "verified": True,
    }


@router.patch("/address-book/{entry_id}", dependencies=[Depends(require_local)])
async def patch_book(
    entry_id: str, body: BookPatch, svc: Services = Depends(services)
) -> dict[str, Any]:
    try:
        ok = await svc.store.update_book_entry(entry_id, label=body.label, verified=body.verified)
    except Exception as exc:  # sqlite IntegrityError: agent entries can never be verified
        raise WardenError(
            "agent-written entries cannot be marked verified; add the address yourself instead",
            code="invalid_request",
        ) from exc
    if not ok:
        raise NotFound(f"address-book entry {entry_id}")
    return {"id": entry_id}


@router.delete("/address-book/{entry_id}", status_code=204, dependencies=[Depends(require_local)])
async def delete_book(entry_id: str, svc: Services = Depends(services)) -> None:
    if not await svc.store.delete_book_entry(entry_id):
        raise NotFound(f"address-book entry {entry_id}")


@router.get("/audit:verify")
async def audit_verify(svc: Services = Depends(services)) -> dict[str, Any]:
    return await svc.store.verify_chain()
