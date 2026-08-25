from contextlib import asynccontextmanager
from typing import Dict, Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from src.model import (
    RevalidateRequest,
    RevalidateResponse,
    DeltaResponse,
    DeltaChange,
    SchedulerRunEntry,
    SchedulerSettingsModel,
    SchedulerStatusResponse,
)
from src.repository import RevalidationRepository
from src.service.delta_engine import DeltaEngine
from src.core.config import load_scheduler_settings
from src.service.scheduler import (
    RevalidationRunner,
    RevalidationScheduler,
    SchedulerBusyError,
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    # Contract clause 7: enabled=false gates automatic scheduling only.
    if scheduler.settings.enabled:
        scheduler.start()
    try:
        yield
    finally:
        scheduler.stop()


app = FastAPI(
    title="OCSF Re-Validation Service",
    version="2.0.0",
    lifespan=lifespan,
)

repository = RevalidationRepository()


def validate_ocsf_event(event: Dict[str, Any]):
    """
    Basic OCSF validation for the re-validation service.
    """

    errors = []

    mandatory_fields = [
        "class_uid",
        "category_uid",
        "time",
    ]

    for field in mandatory_fields:
        if field not in event or event[field] is None:
            errors.append(
                f"Missing mandatory OCSF field: '{field}'"
            )

    event_time = event.get("time")

    if event_time is not None:
        if not isinstance(event_time, (int, float)):
            errors.append(
                "Invalid 'time' type: "
                "Expected numeric timestamp, "
                f"got {type(event_time).__name__}"
            )

    return len(errors) == 0, errors


# -------------------------------------------------
# Scheduler engine (#4) — see SCHEDULER_CONTRACT.md
# -------------------------------------------------

scheduler_settings = load_scheduler_settings()

revalidation_runner = RevalidationRunner(
    repository=repository,
    validator=validate_ocsf_event,
)

scheduler = RevalidationScheduler(
    settings=scheduler_settings,
    runner=revalidation_runner,
    repository=repository,
)


@app.get("/")
def home():
    return {
        "message": "OCSF Re-Validation Service is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post(
    "/api/v2/revalidate",
    response_model=RevalidateResponse,
)
def revalidate(
    request: RevalidateRequest,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
    ),
):
    """
    Trigger an OCSF re-validation run.

    Idempotency guarantees:
    - Same key + same request → return existing result.
    - Same key + different request → HTTP 409.
    """

    # -------------------------------------------------
    # 1. Validate Idempotency-Key
    # -------------------------------------------------

    if not idempotency_key.strip():
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_IDEMPOTENCY_KEY",
                "message": "Idempotency-Key cannot be empty",
            },
        )

    if len(idempotency_key) > 255:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_IDEMPOTENCY_KEY",
                "message": (
                    "Idempotency-Key must not exceed "
                    "255 characters"
                ),
            },
        )

    try:

        # -------------------------------------------------
        # 2. Calculate request hash
        # -------------------------------------------------

        request_hash = repository.build_request_hash(
            event_id=request.event_id,
            original_event=request.original_event,
            updated_event=request.event,
        )

        # -------------------------------------------------
        # 3. Check idempotency
        # -------------------------------------------------

        existing = repository.get_by_idempotency_key(
            idempotency_key
        )

        if existing:

            # Same key + same request
            if existing["request_hash"] == request_hash:

                return RevalidateResponse(
                    re_run_id=existing["re_run_id"],
                    event_id=existing["event_id"],
                    status="already_processed",
                    valid=existing["valid"],
                    errors=existing["errors"],
                    idempotent=True,
                )

            # Same key + different request
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "IDEMPOTENCY_KEY_CONFLICT",
                    "message": (
                        "The Idempotency-Key has already "
                        "been used for a different request"
                    ),
                },
            )

        # -------------------------------------------------
        # 4. Validate event
        # -------------------------------------------------

        valid, errors = validate_ocsf_event(
            request.event
        )

        # -------------------------------------------------
        # 5. Generate re-run ID
        # -------------------------------------------------

        re_run_id = f"rerun-{uuid4().hex}"

        # -------------------------------------------------
        # 6. Save result
        # -------------------------------------------------

        try:

            repository.save(
                re_run_id=re_run_id,
                event_id=request.event_id,
                idempotency_key=idempotency_key,
                original_event=request.original_event,
                updated_event=request.event,
                valid=valid,
                errors=errors,
            )

        except Exception as save_error:

            # A concurrent request may have inserted
            # the same Idempotency-Key between our
            # lookup and INSERT.

            existing = repository.get_by_idempotency_key(
                idempotency_key
            )

            if existing:

                if existing["request_hash"] == request_hash:

                    return RevalidateResponse(
                        re_run_id=existing["re_run_id"],
                        event_id=existing["event_id"],
                        status="already_processed",
                        valid=existing["valid"],
                        errors=existing["errors"],
                        idempotent=True,
                    )

                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "IDEMPOTENCY_KEY_CONFLICT",
                        "message": (
                            "The Idempotency-Key has already "
                            "been used for a different request"
                        ),
                    },
                )

            raise save_error

        # -------------------------------------------------
        # 7. Return response
        # -------------------------------------------------

        return RevalidateResponse(
            re_run_id=re_run_id,
            event_id=request.event_id,
            status="completed",
            valid=valid,
            errors=errors,
            idempotent=False,
        )

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "REVALIDATION_FAILED",
                "message": (
                    "Unable to complete re-validation"
                ),
            },
        )


@app.get(
    "/api/v2/revalidate/{re_run_id}/delta",
    response_model=DeltaResponse,
)
def get_delta(re_run_id: str):

    # -------------------------------------------------
    # 1. Validate re_run_id
    # -------------------------------------------------

    if not re_run_id.strip():
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_RE_RUN_ID",
                "message": "re_run_id cannot be empty",
            },
        )

    try:

        # -------------------------------------------------
        # 2. Find re-validation run
        # -------------------------------------------------

        result = repository.get_by_id(
            re_run_id
        )

        if result is None:

            raise HTTPException(
                status_code=404,
                detail={
                    "code": "RE_RUN_NOT_FOUND",
                    "message": (
                        f"Re-validation run "
                        f"'{re_run_id}' was not found"
                    ),
                },
            )

        # -------------------------------------------------
        # 3. Calculate delta
        # -------------------------------------------------

        changes = DeltaEngine.calculate(
            result["original_event"],
            result["updated_event"],
        )

        # -------------------------------------------------
        # 4. Convert to response model
        # -------------------------------------------------

        delta_changes = [
            DeltaChange(**change)
            for change in changes
        ]

        # -------------------------------------------------
        # 5. Return response
        # -------------------------------------------------

        return DeltaResponse(
            re_run_id=result["re_run_id"],
            event_id=result["event_id"],
            changes=delta_changes,
        )

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "DELTA_CALCULATION_FAILED",
                "message": (
                    "Unable to calculate re-validation delta"
                ),
            },
        )


@app.get(
    "/api/v2/revalidate/scheduler/status",
    response_model=SchedulerStatusResponse,
)
def get_scheduler_status():
    """
    Current scheduler configuration, lifecycle state and recent run history.
    """

    try:

        recent = [
            SchedulerRunEntry(**entry)
            for entry in repository.list_scheduler_history(limit=10)
        ]

        counters = scheduler.counters()

        return SchedulerStatusResponse(
            settings=SchedulerSettingsModel(
                enabled=scheduler.settings.enabled,
                interval_seconds=scheduler.settings.interval_seconds,
            ),
            scheduler_running=scheduler.is_running(),
            runs_started=counters["runs_started"],
            skipped_ticks=counters["skipped_ticks"],
            last_run=next(
                (
                    entry
                    for entry in recent
                    if entry.trigger != "skipped_tick"
                ),
                None,
            ),
            recent_runs=recent,
        )

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "SCHEDULER_STATUS_FAILED",
                "message": "Unable to read scheduler status",
            },
        )


@app.post(
    "/api/v2/revalidate/scheduler/run-now",
    response_model=SchedulerRunEntry,
)
def scheduler_run_now():
    """
    Trigger exactly one re-validation pass through the same single
    execution path used by scheduled ticks (contract clause 1).

    Returns 409 if a run is already active. A runner failure is NOT a
    transport error: it is returned as HTTP 200 with status 'failed'
    plus the recorded error (failures are data — clause 5).
    """

    try:
        result = scheduler.run_once(trigger="manual")
    except SchedulerBusyError as busy_error:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SCHEDULER_RUN_IN_PROGRESS",
                "message": str(busy_error),
            },
        )

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "REVALIDATION_SCHEDULER_FAILED",
                "message": "Unable to trigger re-validation run",
            },
        )

    return SchedulerRunEntry(**result)
