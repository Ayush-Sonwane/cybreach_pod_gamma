# revalidation_service/src/core/contracts.py
"""Re-Validation & Delta Report Schemas (Pod Gamma, Task 3)."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class RuleRef(BaseModel):
    """One mapping rule. A rule id is scoped per OCSF field
    (e.g. ``map.splunk.status_id``) and versioned by the mapped schema."""

    rule_id: str
    version: str
    source: str = ""


class ValidationResult(BaseModel):
    is_valid: bool = True
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class ConfidenceScore(BaseModel):
    score: float = 100.0
    reasons: List[str] = Field(default_factory=list)


class EventSnapshot(BaseModel):
    """A normalized OCSF event plus its validation, confidence and rules."""

    event_id: str
    vendor: str
    normalized: Dict[str, Any] = Field(default_factory=dict)
    metadata_version: Optional[str] = None
    verdict: ValidationResult = Field(default_factory=ValidationResult)
    confidence: ConfidenceScore = Field(default_factory=ConfidenceScore)
    rules_used: List[RuleRef] = Field(default_factory=list)


ChangeType = Literal["ADDED", "REMOVED", "CHANGED", "UNCHANGED"]


class DeltaEntry(BaseModel):
    ocsf_field: str
    change_type: ChangeType
    old_value: Any = None
    new_value: Any = None
    rule_id: Optional[str] = None


RunVerdict = Literal["IMPROVED", "DEGRADED", "UNCHANGED"]


class RevalidationRun(BaseModel):
    """One re-validation run: before vs after comparison record."""

    run_id: str
    event_id: str
    vendor: str
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    verdict: RunVerdict
    confidence_before: float
    confidence_after: float
    confidence_delta: float
    valid_before: bool
    valid_after: bool
    deltas: List[DeltaEntry] = Field(default_factory=list)
    improved_by: List[str] = Field(default_factory=list)
    degraded_by: List[str] = Field(default_factory=list)
    before: EventSnapshot
    after: EventSnapshot


class RuleVersionComparison(BaseModel):
    """Comparison of rule ids/versions between two runs or two schema versions."""

    rule_id: str
    before_version: Optional[str] = None
    after_version: Optional[str] = None
    version_changed: bool = False
    added_fields: List[str] = Field(default_factory=list)
    removed_fields: List[str] = Field(default_factory=list)


class ImprovementReport(BaseModel):
    """Aggregate improvement metrics across all stored re-validation runs."""

    total_runs: int = 0
    improved_runs: int = 0
    degraded_runs: int = 0
    unchanged_runs: int = 0
    avg_confidence_delta: float = 0.0
    total_confidence_change: float = 0.0
    top_rules_for_improvement: List[Dict[str, Any]] = Field(default_factory=list)