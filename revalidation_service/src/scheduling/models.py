"""Pydantic models for re-validation schedule management."""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, BeforeValidator, Field
from typing import Annotated

from src.scheduling.interval import (
    DEFAULT_INTERVAL,
    parse_interval,
)

IntervalSeconds = Annotated[int, BeforeValidator(parse_interval)]

MissedRunPolicy = Literal["skip", "run_once"]


class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    event_id: str = Field(..., min_length=1)
    interval: IntervalSeconds = Field(
        default=parse_interval(DEFAULT_INTERVAL),
        description="Re-validation cadence, e.g. '15m', '6h', '7d'",
    )
    missed_run_policy: MissedRunPolicy = "run_once"
    request_template: Optional[Dict[str, Any]] = None


class ScheduleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    interval: Optional[IntervalSeconds] = None
    missed_run_policy: Optional[MissedRunPolicy] = None
    enabled: Optional[bool] = None
    request_template: Optional[Dict[str, Any]] = None


class ScheduleResponse(BaseModel):
    schedule_id: str
    name: str
    event_id: str
    interval_seconds: int
    missed_run_policy: MissedRunPolicy
    enabled: bool
    has_request_template: bool
    is_running: bool = False
    last_run_at: Optional[float] = None
    next_run_at: Optional[float] = None
    created_at: str
    updated_at: str


class ScheduleListResponse(BaseModel):
    schedules: List[ScheduleResponse] = Field(default_factory=list)
    count: int = 0


class DeleteScheduleResponse(BaseModel):
    schedule_id: str
    deleted: bool
