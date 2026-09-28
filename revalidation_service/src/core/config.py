# revalidation_service/src/core/config.py
import os
from dataclasses import dataclass, field

PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Canonical topic names, plan Section 5.
#
# P5: these were "declared nowhere", so any pod wiring itself to the bus in a
# later run had no single place to read the names from. They are declared here
# so all four pods agree, and the broker is injected via the environment
# rather than hardcoded to `localhost:9092` -- a hardcoded address silently
# points at whatever broker happens to be on the developer's own machine.
#
# Note: Pod Gamma has no boot-task ownership in the first hybrid run
# (integration_run_plan.md), so nothing subscribes or publishes here yet. These
# constants exist to keep the names canonical, not to imply a consumer exists.
TOPIC_EVIDENCE = os.getenv("KAFKA_TOPIC_EVIDENCE", "cybreach.evidence.v1")
TOPIC_VERDICTS = os.getenv("KAFKA_TOPIC_VERDICTS", "cybreach.verdicts.v2")
TOPIC_GAP_CLOSED = os.getenv("KAFKA_TOPIC_GAP_CLOSED", "cybreach.gap_closed.v2")
TOPIC_REVALIDATION = os.getenv("KAFKA_TOPIC_REVALIDATION", "cybreach.revalidation.v1")
TOPIC_CONNECTOR_HEALTH = os.getenv(
    "KAFKA_TOPIC_CONNECTOR_HEALTH", "cybreach.connector.health.v1"
)

PLAN_TOPICS = (
    TOPIC_EVIDENCE,
    TOPIC_VERDICTS,
    TOPIC_GAP_CLOSED,
    TOPIC_REVALIDATION,
    TOPIC_CONNECTOR_HEALTH,
)


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

    # Injected message bus. Only consumed once Gamma is given bus ownership.
    kafka_bootstrap_servers: str = field(
        default_factory=lambda: os.getenv("KAFKA_BOOTSTRAP_SERVERS", "")
    )

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