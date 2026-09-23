# revalidation_service/src/service/scoring.py
"""Confidence scoring and rule extraction (Pod Gamma, Task 3).

Confidence formula: score starts at 100 and deducts configurable weights for
known quality gaps:

- `validation_error`    per validator error
- `missing_actor`       no actor/user context (Authentication class)
- `missing_endpoint`    per missing src/dst endpoint
- `unknown_status`      status_id == 99
- `default_severity`    severity_id absent or 1
- `empty_provenance`    no field-level provenance recorded
"""
from typing import Any, Dict, List

from src.core.config import get_settings
from src.core.contracts import ConfidenceScore, RuleRef, ValidationResult
from src.service.validator import validate_event


def rules_used(event: Dict[str, Any], vendor: str) -> List[RuleRef]:
    """Derive mapping rules from metadata.provenance entries + schema version."""
    metadata = event.get("metadata")
    version = None
    if isinstance(metadata, dict):
        version = metadata.get("version")
    version = version or "1.1.0"

    provenance = []
    if isinstance(metadata, dict):
        raw_prov = metadata.get("provenance")
        if isinstance(raw_prov, list):
            provenance = raw_prov

    rules: List[RuleRef] = []
    for entry in provenance:
        if not isinstance(entry, dict):
            continue
        ocsf_field = entry.get("ocsf_field")
        raw_field = entry.get("raw_field")
        if not ocsf_field:
            continue
        rules.append(
            RuleRef(
                rule_id=f"map.{vendor}.{ocsf_field}",
                version=str(version),
                source=f"raw.{raw_field}" if raw_field else "adapter",
            )
        )
    if not rules:
        rules.append(
            RuleRef(rule_id=f"map.{vendor}.base", version=str(version), source="adapter")
        )
    return rules


def compute_confidence(
    event: Dict[str, Any],
    validation: ValidationResult,
    vendor: str = "unknown",
) -> ConfidenceScore:
    weights = get_settings().weights
    floor = get_settings().confidence_floor

    score = 100.0
    reasons: List[str] = []

    for error in validation.errors:
        score -= float(weights["validation_error"])
        reasons.append(f"validation error: {error}")

    if event.get("class_uid") == 3002 and "actor" not in event and "user" not in event:
        score -= float(weights["missing_actor"])
        reasons.append("no actor/user context")

    for endpoint in ("src_endpoint", "dst_endpoint"):
        if event.get(endpoint) is None:
            score -= float(weights["missing_endpoint"])
            reasons.append(f"missing {endpoint}")

    if event.get("status_id") == 99:
        score -= float(weights["unknown_status"])
        reasons.append("status_id is 99 (unknown)")

    if event.get("severity_id") in (None, 1):
        score -= float(weights["default_severity"])
        reasons.append("severity_id absent or default (1)")

    metadata = event.get("metadata")
    provenance = metadata.get("provenance") if isinstance(metadata, dict) else None
    if not isinstance(provenance, list) or len(provenance) == 0:
        score -= float(weights["empty_provenance"])
        reasons.append("no field-level provenance recorded")

    return ConfidenceScore(score=max(floor, round(score, 2)), reasons=reasons)


def build_snapshot(event_id: str, vendor: str, event: Dict[str, Any]) -> Any:
    """Build an EventSnapshot (validation + confidence + rules) for an event dict."""
    from src.core.contracts import EventSnapshot

    validation = validate_event(event)
    confidence = compute_confidence(event, validation, vendor)
    return EventSnapshot(
        event_id=event_id,
        vendor=vendor,
        normalized=event,
        metadata_version=event.get("metadata", {}).get("version") if isinstance(event.get("metadata"), dict) else None,
        verdict=validation,
        confidence=confidence,
        rules_used=rules_used(event, vendor),
    )