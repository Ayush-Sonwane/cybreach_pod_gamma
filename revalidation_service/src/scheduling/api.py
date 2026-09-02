"""Management API for automated re-validation schedules.

These endpoints only manage schedule configuration and run
bookkeeping; triggering runs is the scheduler engine's job.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from src.scheduling import models
from src.scheduling.repository import (
    DuplicateScheduleError,
    ScheduleRepository,
)

router = APIRouter(
    prefix="/api/v2/revalidate/schedules",
    tags=["Re-Validation Schedules"],
)

schedule_repository = ScheduleRepository()


def get_schedule_repository() -> ScheduleRepository:
    return schedule_repository


@router.post(
    "",
    response_model=models.ScheduleResponse,
    status_code=201,
)
def create_schedule(
    request: models.ScheduleCreate,
    repository: ScheduleRepository = Depends(get_schedule_repository),
):

    try:
        record = repository.create(
            name=request.name.strip(),
            event_id=request.event_id.strip(),
            interval_seconds=request.interval,
            missed_run_policy=request.missed_run_policy,
            enabled=True,
            request_template=request.request_template,
        )
    except DuplicateScheduleError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SCHEDULE_ALREADY_EXISTS",
                "message": "A schedule with the generated id already exists",
            },
        )

    return _to_response(record)


@router.get(
    "",
    response_model=models.ScheduleListResponse,
)
def list_schedules(
    enabled: Optional[bool] = Query(None),
    repository: ScheduleRepository = Depends(get_schedule_repository),
):

    records = repository.list(enabled=enabled)

    return models.ScheduleListResponse(
        schedules=[_to_response(record) for record in records],
        count=len(records),
    )


@router.get(
    "/{schedule_id}",
    response_model=models.ScheduleResponse,
)
def get_schedule(
    schedule_id: str,
    repository: ScheduleRepository = Depends(get_schedule_repository),
):

    record = repository.get(schedule_id)

    if record is None:
        raise _not_found(schedule_id)

    return _to_response(record)


@router.patch(
    "/{schedule_id}",
    response_model=models.ScheduleResponse,
)
def update_schedule(
    schedule_id: str,
    request: models.ScheduleUpdate,
    repository: ScheduleRepository = Depends(get_schedule_repository),
):

    fields = {
        key: value
        for key, value in request.model_dump(exclude_unset=True).items()
        if value is not None or key == "request_template"
    }

    if not fields:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "EMPTY_SCHEDULE_UPDATE",
                "message": "At least one field must be provided",
            },
        )

    column_fields = {}

    if "name" in fields:
        column_fields["name"] = fields["name"].strip()

    if "interval" in fields:
        column_fields["interval_seconds"] = fields["interval"]

    if "missed_run_policy" in fields:
        column_fields["missed_run_policy"] = fields["missed_run_policy"]

    if "enabled" in fields:
        column_fields["enabled"] = fields["enabled"]

    if "request_template" in fields:
        column_fields["request_template"] = fields["request_template"]

    record = repository.update(schedule_id, column_fields)

    if record is None:
        raise _not_found(schedule_id)

    return _to_response(record)


@router.delete(
    "/{schedule_id}",
    response_model=models.DeleteScheduleResponse,
)
def delete_schedule(
    schedule_id: str,
    repository: ScheduleRepository = Depends(get_schedule_repository),
):

    deleted = repository.delete(schedule_id)

    if not deleted:
        raise _not_found(schedule_id)

    return models.DeleteScheduleResponse(
        schedule_id=schedule_id,
        deleted=True,
    )


def _not_found(schedule_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "code": "SCHEDULE_NOT_FOUND",
            "message": f"Schedule '{schedule_id}' was not found",
        },
    )


def _to_response(record) -> models.ScheduleResponse:
    return models.ScheduleResponse(
        schedule_id=record["schedule_id"],
        name=record["name"],
        event_id=record["event_id"],
        interval_seconds=record["interval_seconds"],
        missed_run_policy=record["missed_run_policy"],
        enabled=record["enabled"],
        has_request_template=record["request_template"] is not None,
        is_running=record["is_running"],
        last_run_at=record["last_run_at"],
        next_run_at=record["next_run_at"],
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )
