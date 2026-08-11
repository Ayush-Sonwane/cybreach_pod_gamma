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