"""
Scheduler configuration for the re-validation service.

Contract: see revalidation_service/SCHEDULER_CONTRACT.md ("Configuration" section).
This module is the ONLY sanctioned seam for scheduler configuration; the #5 interval
configuration layer must operate through SchedulerSettings and never mutate engine
internals directly.

Fail-fast rule (frozen clause 8):
  - Missing env vars -> documented defaults.
  - Present-but-invalid values -> ValueError with a clear message (never silent fallback).
"""

import os
from dataclasses import dataclass
from typing import Mapping, Optional

ENV_ENABLED = "REVALIDATION_SCHEDULER_ENABLED"
ENV_INTERVAL_SECONDS = "REVALIDATION_SCHEDULER_INTERVAL_SECONDS"

DEFAULT_ENABLED = False
DEFAULT_INTERVAL_SECONDS = 300

_TRUE_VALUES = {"true", "1"}
_FALSE_VALUES = {"false", "0"}


@dataclass(frozen=True)
class SchedulerSettings:
    """Immutable snapshot of scheduler configuration."""

    enabled: bool = DEFAULT_ENABLED
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS


def load_scheduler_settings(environ: Optional[Mapping[str, str]] = None) -> SchedulerSettings:
    """Load scheduler settings from environment variables.

    Accepts an explicit mapping for testing; defaults to os.environ.
    Raises ValueError on any present-but-invalid value (fail fast).
    """
    source = os.environ if environ is None else environ

    enabled_raw = source.get(ENV_ENABLED)
    if enabled_raw is None:
        enabled = DEFAULT_ENABLED
    else:
        normalized = enabled_raw.strip().lower()
        if normalized in _TRUE_VALUES:
            enabled = True
        elif normalized in _FALSE_VALUES:
            enabled = False
        else:
            raise ValueError(
                f"Invalid {ENV_ENABLED}={enabled_raw!r}: accepted values are true/false/1/0"
            )

    interval_raw = source.get(ENV_INTERVAL_SECONDS)
    if interval_raw is None:
        interval = DEFAULT_INTERVAL_SECONDS
    else:
        try:
            interval = int(interval_raw.strip())
        except ValueError:
            raise ValueError(
                f"Invalid {ENV_INTERVAL_SECONDS}={interval_raw!r}: must be an integer >= 1"
            ) from None
        if interval < 1:
            raise ValueError(
                f"Invalid {ENV_INTERVAL_SECONDS}={interval_raw!r}: must be an integer >= 1"
            )

    return SchedulerSettings(enabled=enabled, interval_seconds=interval)
