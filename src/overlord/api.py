from __future__ import annotations

import hmac
import logging
import os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, ValidationError

from .gates import (
    assign_tier,
    audit_window,
    compress_evidence,
    evaluate_min_support,
    evaluate_triangulation,
)
from .models import SCHEMAS, get_schema, validate_agent_output
from .pending import PendingStore
from .pipeline import STAGES, OverlordPipeline, summarise_incident
from .sanitize import sanitize_telemetry
from .store import OllamaEmbedder, OverlordStore, QdrantIndex

app = FastAPI(title="Overlord Deterministic Core", version="0.2.0")

_STATE_DIR = Path(
    os.getenv("OVERLORD_STATE_DIR", str(Path.home() / ".local" / "state" / "overlord"))
)
_PENDING = PendingStore(_STATE_DIR / "pending.json")
log = logging.getLogger(__name__)
PARKED_ERRORS = frozenset({"awaiting_approval", "authorization_required"})


def require_token(authorization: str | None = Header(default=None)) -> None:
    """Protect endpoints that act or expose records; fail closed without a token."""
    expected = os.getenv("OVERLORD_API_TOKEN")
    if not expected:
        if os.getenv("OVERLORD_ALLOW_UNAUTHENTICATED") == "1":
            return
        raise HTTPException(status_code=503, detail="OVERLORD_API_TOKEN is not configured")
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="invalid or missing API token")


if not os.getenv("OVERLORD_API_TOKEN"):
    log.warning("OVERLORD_API_TOKEN is unset: pipeline and store endpoints will refuse requests")


def _build_store() -> OverlordStore | None:
    if os.getenv("OVERLORD_PERSIST", "0") != "1":
        return None
    vector = QdrantIndex(
        os.getenv("OVERLORD_QDRANT_URL", "http://127.0.0.1:6350"),
        embedder=OllamaEmbedder(os.getenv("OVERLORD_EMBED_MODEL", "nomic-embed-text")),
    )
    return OverlordStore(_STATE_DIR / "ledger.db", vector)


_STORE = _build_store()


def _pipeline() -> OverlordPipeline:
    return OverlordPipeline(store=_STORE)


class SanitizeRequest(BaseModel):
    text: str


class MinSupportRequest(BaseModel):
    hypothesis: str
    supporting_facts: list[str]
    facts_by_id: dict[str, dict[str, Any]]
    now: datetime | None = None


class TriangulationRequest(BaseModel):
    justification: list[str]


class WindowAuditRequest(BaseModel):
    evidence_summary: str
    supporting_facts: list[str] = Field(default_factory=list)
    model_context_window: int


class TierRequest(BaseModel):
    requested_tier: int
    asset_class: str
    tier0_action_permitted: bool = True


class CompressionRequest(BaseModel):
    evidence_summary: str
    tags: list[str] = Field(default_factory=list)
    delta_tokens: int = 0


class PipelineRequest(BaseModel):
    telemetry: list[dict[str, Any]]
    requested_tier: int = 1
    asset_class: str = "endpoint_workstation"
    target_asset: str = "host-42"
    approve: bool | None = None
    authorization: str | None = None
    model_context_window: int = 8192
    stop_after: str | None = None
    auto_sensors: bool = False


class ApprovalRequest(BaseModel):
    authorization: str | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/schemas")
def list_schemas() -> dict[str, list[str]]:
    return {"schemas": sorted(SCHEMAS)}


@app.get("/schemas/{name}")
def read_schema(name: str) -> dict[str, Any]:
    try:
        return get_schema(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/sanitize")
def post_sanitize(request: SanitizeRequest) -> dict[str, Any]:
    return asdict(sanitize_telemetry(request.text))


@app.post("/gates/min-support")
def post_min_support(request: MinSupportRequest) -> dict[str, Any]:
    return asdict(
        evaluate_min_support(
            request.hypothesis,
            request.supporting_facts,
            request.facts_by_id,
            request.now,
        )
    )


@app.post("/gates/triangulation")
def post_triangulation(request: TriangulationRequest) -> dict[str, Any]:
    return asdict(evaluate_triangulation(request.justification))


@app.post("/gates/window-audit")
def post_window_audit(request: WindowAuditRequest) -> dict[str, Any]:
    return asdict(
        audit_window(
            request.evidence_summary,
            request.supporting_facts,
            request.model_context_window,
        )
    )


@app.post("/gates/tier")
def post_tier(request: TierRequest) -> dict[str, Any]:
    return asdict(
        assign_tier(
            request.requested_tier,
            request.asset_class,
            request.tier0_action_permitted,
        )
    )


@app.post("/gates/compress")
def post_compress(request: CompressionRequest) -> dict[str, Any]:
    return asdict(
        compress_evidence(
            request.evidence_summary,
            request.tags,
            request.delta_tokens,
        )
    )


@app.get("/pipeline/stages")
def list_stages() -> dict[str, list[str]]:
    return {"stages": list(STAGES)}


@app.post("/pipeline/run", dependencies=[Depends(require_token)])
def post_pipeline(request: PipelineRequest) -> dict[str, Any]:
    # A caller must not approve its own request: approval is a separate step.
    if (request.approve is True or request.authorization) and os.getenv(
        "OVERLORD_ALLOW_INLINE_APPROVAL"
    ) != "1":
        raise HTTPException(
            status_code=400,
            detail="approve through /pipeline/approve/{decision_id}, not /pipeline/run",
        )
    pipeline = OverlordPipeline(
        model_context_window=request.model_context_window,
        auto_sensors=request.auto_sensors,
        store=_STORE,
    )
    try:
        result = pipeline.run_incident(
            request.telemetry,
            requested_tier=request.requested_tier,
            asset_class=request.asset_class,
            target_asset=request.target_asset,
            approve=request.approve,
            authorization=request.authorization,
            stop_after=request.stop_after,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result.blocked_at == "S7" and result.error in PARKED_ERRORS:
        _PENDING.park(result)
    return {"summary": summarise_incident(result), "result": result.to_dict()}


@app.get("/pipeline/pending", dependencies=[Depends(require_token)])
def list_pending() -> dict[str, Any]:
    return {"pending": _PENDING.all()}


@app.post("/pipeline/approve/{decision_id}", dependencies=[Depends(require_token)])
def approve_decision(
    decision_id: str, request: ApprovalRequest | None = None
) -> dict[str, Any]:
    parked = _PENDING.claim(decision_id)
    if parked is None:
        raise HTTPException(status_code=404, detail="unknown decision_id")
    try:
        result = _pipeline().resume(
            parked,
            approve=True,
            authorization=request.authorization if request else None,
        )
    except Exception:
        _PENDING.restore(decision_id, parked)
        raise
    if result.error in {"authorization_required", "authorization_invalid"}:
        _PENDING.restore(decision_id, parked)
        raise HTTPException(status_code=403, detail=result.error)
    return {"summary": summarise_incident(result), "result": result.to_dict()}


@app.post("/pipeline/cancel/{decision_id}", dependencies=[Depends(require_token)])
def cancel_decision(decision_id: str) -> dict[str, Any]:
    parked = _PENDING.claim(decision_id)
    if parked is None:
        raise HTTPException(status_code=404, detail="unknown decision_id")
    result = _pipeline().resume(parked, approve=False)
    return {"summary": summarise_incident(result), "result": result.to_dict()}


@app.get("/store/stats", dependencies=[Depends(require_token)])
def store_stats() -> dict[str, Any]:
    if _STORE is None:
        raise HTTPException(status_code=503, detail="persistence disabled")
    return _STORE.stats()


@app.get("/store/search", dependencies=[Depends(require_token)])
def store_search(q: str, kind: str | None = None, limit: int = 10) -> dict[str, Any]:
    if _STORE is None:
        raise HTTPException(status_code=503, detail="persistence disabled")
    return _STORE.search(q, kind=kind, limit=limit)


@app.get("/store/{kind}/{record_id}", dependencies=[Depends(require_token)])
def store_get(kind: str, record_id: str) -> dict[str, Any]:
    if _STORE is None:
        raise HTTPException(status_code=503, detail="persistence disabled")
    record = _STORE.get(kind, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown record")
    return record


@app.post("/validate/conclusion")
def post_validate_conclusion(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        conclusion = validate_agent_output(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    return {"valid": True, "conclusion": conclusion.model_dump(mode="json")}


def main() -> None:
    import uvicorn

    uvicorn.run("overlord.api:app", host="127.0.0.1", port=8790)
