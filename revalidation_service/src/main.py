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

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from src.core.config import get_settings
from src.core.contracts import (
    EventSnapshot,
    ImprovementReport,
    RevalidationRun,
    RuleVersionComparison,
)
from src.security import get_current_claims, get_current_tenant
from src.service.delta_engine import (
    build_report,
    compare_rule_versions,
    evaluate,
)
from src.service.history_store import RevalidationHistoryStore
from src.service.scoring import build_snapshot
from src.wallet import wallet

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


@app.get("/health")
def health():
    return {"status": "ok", "service": "revalidation-service"}


# B11: every /api/v2 route below requires the module's shared JWT. The guard is
# declared per-route rather than as an app-level `dependencies=` so that `/` and
# `/health` stay reachable without a credential for the run plan's cross-pod
# health check.
_REAUTH = [Depends(get_current_claims)]


@app.post("/api/v2/revalidate", response_model=RevalidationRun, dependencies=_REAUTH)
def revalidate(
    request: RevalidateRequest,
    tenant_id: str = Depends(get_current_tenant),
):
    """Validate/normalizer result vs the event's last stored run.

    First submission for an event_id compares against an empty baseline,
    so even the initial result produces a measurable improvement delta.

    Re-validation debits 1 credit per run (plan Section 9); the credit is
    refunded when the run verdict is UNCHANGED (no meaningful delta).
    """
    if not request.normalized:
        raise HTTPException(status_code=400, detail="'normalized' payload must not be empty")

    if not wallet.debit(1):
        raise HTTPException(status_code=402, detail="insufficient credits")

    after = build_snapshot(request.event_id, request.vendor, request.normalized)
    before = store.latest_after(request.event_id, tenant_id) or _baseline_snapshot(
        request.event_id, request.vendor
    )

    run = evaluate(before, after, run_id=uuid.uuid4().hex)
    store.save_run(run, tenant_id)

    if run.verdict == "UNCHANGED":
        wallet.refund(1)

    return run


@app.get("/api/v2/revalidate/wallet", dependencies=_REAUTH)
def wallet_balance(
    tenant_id: str = Depends(get_current_tenant),
):
    """Current credit balance for the mock wallet client (plan Section 9)."""
    return {"balance": wallet.get_balance()}


@app.post(
    "/api/v2/revalidate/compare",
    response_model=RevalidationRun,
    dependencies=_REAUTH,
)
def revalidate_compare(
    request: CompareRequest,
    tenant_id: str = Depends(get_current_tenant),
):
    """Stateless comparison of two explicit before/after normalized payloads."""
    before = build_snapshot(request.event_id, request.vendor, request.before)
    after = build_snapshot(request.event_id, request.vendor, request.normalized)
    return evaluate(before, after, run_id=uuid.uuid4().hex)


@app.get(
    "/api/v2/revalidate/runs",
    response_model=List[RevalidationRun],
    dependencies=_REAUTH,
)
def list_runs(
    limit: int = Query(50, ge=1, le=1000),
    event_id: Optional[str] = None,
    tenant_id: str = Depends(get_current_tenant),
):
    return store.list_runs(limit=limit, event_id=event_id, tenant_id=tenant_id)


@app.get(
    "/api/v2/revalidate/runs/{run_id}",
    response_model=RevalidationRun,
    dependencies=_REAUTH,
)
def get_run(
    run_id: str,
    tenant_id: str = Depends(get_current_tenant),
):
    run = store.get_run(run_id, tenant_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"run '{run_id}' not found")
    return run


@app.get(
    "/api/v2/revalidate/metrics",
    response_model=ImprovementReport,
    dependencies=_REAUTH,
)
def improvement_metrics(tenant_id: str = Depends(get_current_tenant)):
    """Improvement metrics across this tenant's stored re-validation runs.

    Scoped per tenant: a module-wide average would leak another tenant's
    detection quality and make this number meaningless as a tenant's own metric.
    """
    return build_report(store.all_runs(tenant_id))


@app.get(
    "/api/v2/revalidate/rules/compare",
    response_model=List[RuleVersionComparison],
    dependencies=_REAUTH,
)
def rule_version_comparison(
    v1: str = Query(..., description="before schema version, e.g. 1.0.0"),
    v2: str = Query(..., description="after schema version, e.g. 1.1.0"),
    tenant_id: str = Depends(get_current_tenant),
):
    """History-based rule/version comparison: rule sets recorded at v1 vs v2."""
    return compare_rule_versions(store.all_runs(tenant_id), v1, v2)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8006)