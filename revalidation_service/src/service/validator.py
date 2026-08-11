# revalidation_service/src/service/validator.py
"""Lightweight OCSF validation, mirroring the normalizer's OCSFValidator."""
from typing import Any, Dict

from src.core.contracts import ValidationResult

MANDATORY_BASE_FIELDS = ["class_uid", "category_uid", "time"]

COMPLEX_OBJECT_FIELDS = [
    "user", "actor", "src_endpoint", "dst_endpoint", "file", "process", "device",
]


def validate_event(event: Dict[str, Any]) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    for field in MANDATORY_BASE_FIELDS:
        if field not in event or event[field] is None:
            errors.append(f"Missing mandatory OCSF field: '{field}'")

    event_time = event.get("time")
    if event_time is not None and not isinstance(event_time, (int, float)):
        errors.append(
            f"Invalid 'time' type: Expected numeric timestamp, got {type(event_time).__name__}"
        )

    for field in COMPLEX_OBJECT_FIELDS:
        value = event.get(field)
        if value is not None and not isinstance(value, dict):
            errors.append(
                f"Invalid '{field}': Expected object/dict, got {type(value).__name__}"
            )

    if event.get("class_uid") == 3002:
        if "user" not in event and "actor" not in event:
            errors.append("Class 3002 (Authentication) missing 'user' or 'actor' context")

    severity_id = event.get("severity_id")
    if severity_id is not None and not isinstance(severity_id, int):
        errors.append(
            f"Invalid 'severity_id': Expected integer, got {type(severity_id).__name__}"
        )
    status_id = event.get("status_id")
    if status_id is not None and not isinstance(status_id, int):
        errors.append(
            f"Invalid 'status_id': Expected integer, got {type(status_id).__name__}"
        )

    return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)