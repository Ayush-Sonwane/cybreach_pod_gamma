<<<<<<< HEAD
# revalidation_service/src/core/config.py
import os
from dataclasses import dataclass, field

PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class RevalidationSettings:
    """Application settings for the Re-Validation Service (Pod Gamma, Task 3).

    Confidence score: starts at 100 and deducts the weights below for known
    quality gaps. All weights are config-adjustable.
    """
    service_name: str = "OCSF Re-Validation Service"
    service_version: str = "1.0.0"
    data_dir: str = os.path.join(PACKAGE_ROOT, "data")
    db_path: str = ""

    # Verdict thresholds (confidence delta points)
    improved_threshold: float = 5.0
    degraded_threshold: float = -5.0

    confidence_floor: float = 0.0

    # Confidence deductions
    weights: dict = field(default_factory=lambda: {
        "validation_error": 15.0,    # per validation error
        "missing_actor": 8.0,        # no actor/user context for Authentication
        "missing_endpoint": 4.0,     # per missing src/dst endpoint
        "unknown_status": 5.0,       # status_id == 99
        "default_severity": 3.0,     # severity_id absent or 1 (unknown/lowest)
        "empty_provenance": 5.0,     # no field-level provenance recorded
    })


_settings: RevalidationSettings | None = None


def get_settings() -> RevalidationSettings:
    global _settings
    if _settings is None:
        _settings = RevalidationSettings()
        if not _settings.db_path:
            os.makedirs(_settings.data_dir, exist_ok=True)
            _settings.db_path = os.path.join(_settings.data_dir, "revalidation.db")
    return _settings
=======
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
>>>>>>> 6f2d21fd01ab3671b3a4d6f256dbb9e2a1876f1f
