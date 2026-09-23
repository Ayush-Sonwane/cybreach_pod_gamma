# revalidation_service/src/main.py
"""OCSF Re-Validation Service - FastAPI application (Pod Gamma, Task 3).

Exposes the re-validation engine built for Task 3:
  - delta tracking (field-level before/after diff)
  - rule/version comparison
  - run history with before-and-after verdicts and confidence score changes
  - rules responsible for improvements
  - improvement metrics

Note: full API hardening (error handling, idempotency) is scope of Task 4.
"""
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from src.core.config import get_settings
from src.core.contracts import (
    EventSnapshot,
    ImprovementReport,
    RevalidationRun,
    RuleVersionComparison,
)
from src.service.delta_engine import (
    build_report,
    compare_rule_versions,
    evaluate,
)
from src.service.history_store import RevalidationHistoryStore
from src.service.scoring import build_snapshot

settings = get_settings()
store = RevalidationHistoryStore(settings.db_path)

app = FastAPI(
    title=settings.service_name,
    version=settings.service_version,
)


class RevalidateRequest(BaseModel):
    event_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    normalized: Dict[str, Any]


class CompareRequest(RevalidateRequest):
    before: Dict[str, Any]


def _baseline_snapshot(event_id: str, vendor: str) -> EventSnapshot:
    """Synthetic empty-baseline snapshot used when an event has no history yet."""
    snapshot = build_snapshot(event_id, vendor, {})
    snapshot.rules_used = []
    return snapshot


@app.get("/")
def home():
    return {"message": f"{settings.service_name} is running"}


@app.post("/api/v2/revalidate", response_model=RevalidationRun)
def revalidate(request: RevalidateRequest):
    """Validate/normalizer result vs the event's last stored run.

    First submission for an event_id compares against an empty baseline,
    so even the initial result produces a measurable improvement delta.
    """
    if not request.normalized:
        raise HTTPException(status_code=400, detail="'normalized' payload must not be empty")

    after = build_snapshot(request.event_id, request.vendor, request.normalized)
    before = store.latest_after(request.event_id) or _baseline_snapshot(
        request.event_id, request.vendor
    )

    run = evaluate(before, after, run_id=uuid.uuid4().hex)
    store.save_run(run)
    return run


@app.post("/api/v2/revalidate/compare", response_model=RevalidationRun)
def revalidate_compare(request: CompareRequest):
    """Stateless comparison of two explicit before/after normalized payloads."""
    before = build_snapshot(request.event_id, request.vendor, request.before)
    after = build_snapshot(request.event_id, request.vendor, request.normalized)
    return evaluate(before, after, run_id=uuid.uuid4().hex)


@app.get("/api/v2/revalidate/runs", response_model=List[RevalidationRun])
def list_runs(
    limit: int = Query(50, ge=1, le=1000),
    event_id: Optional[str] = None,
):
    return store.list_runs(limit=limit, event_id=event_id)


@app.get("/api/v2/revalidate/runs/{run_id}", response_model=RevalidationRun)
def get_run(run_id: str):
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"run '{run_id}' not found")
    return run


@app.get("/api/v2/revalidate/metrics", response_model=ImprovementReport)
def improvement_metrics():
    """Improvement metrics across all stored re-validation runs."""
    return build_report(store.all_runs())


@app.get("/api/v2/revalidate/rules/compare", response_model=List[RuleVersionComparison])
def rule_version_comparison(
    v1: str = Query(..., description="before schema version, e.g. 1.0.0"),
    v2: str = Query(..., description="after schema version, e.g. 1.1.0"),
):
    """History-based rule/version comparison: rule sets recorded at v1 vs v2."""
    return compare_rule_versions(store.all_runs(), v1, v2)