"""
Cross-pod wiring gap probe (REPORT ONLY - no fixes here).

The re-validation service validates the updated event with its own
simplified ``validate_ocsf_event`` (class_uid / category_uid / time only).
The inter-pod ``NormalizationContractValidator`` (Pod Gamma task 2b) enforces
the full OCSF schema + provenance contract.  This suite measures how many
contract-invalid events the service silently accepts, so the gap can be
sized and reported to the service owner.  Assertions deliberately lock in the
CURRENT behavior; they are documentation, not a spec.
"""
import pytest
from fastapi.testclient import TestClient

import src.main as main_module
from src.repository import RevalidationRepository
from src.service.scheduler import RevalidationRunner, RevalidationScheduler
from src.core.config import SchedulerSettings

# OCSF contract rules mirrored from the inter-pod validator (task 2b):
#   - severity_id must be in [1, 6]
#   - class 3002 (Authentication) requires user or actor
#   - a metadata block with version + provenance is mandatory
CONTRACT_EXPECTS = {
    "severity_id_out_of_range": ["Invalid 'severity_id': Value 99 out of range [1, 6]"],
    "missing_user_actor": [
        "Class 3002 (Authentication) requires 'user' or 'actor'",
        "Missing mandatory 'metadata' block",
        "Missing 'metadata' dict on normalized event",
    ],
    "missing_metadata": [
        "Missing mandatory 'metadata' block",
        "Missing 'metadata' dict on normalized event",
    ],
}


def _minimal(class_uid=3002, category_uid=3, time=None):
    return {"class_uid": class_uid, "category_uid": category_uid,
            "time": time if time is not None else 1700000000}


@pytest.fixture()
def probe_client(tmp_path, monkeypatch):
    repository = RevalidationRepository(database_path=str(tmp_path / "probe.db"))
    runner = RevalidationRunner(repository=repository, validator=main_module.validate_ocsf_event)
    scheduler = RevalidationScheduler(settings=SchedulerSettings(), runner=runner, repository=repository)
    monkeypatch.setattr(main_module, "repository", repository)
    monkeypatch.setattr(main_module, "scheduler", scheduler)
    with TestClient(main_module.app) as client:
        yield client


def _service_rejects(client, updated_event):
    """True when the simplified in-service validator flags the event."""
    response = client.post(
        "/api/v2/revalidate",
        headers={"Idempotency-Key": "probe"},
        json={"event_id": "evt-probe", "original_event": {}, "event": updated_event},
    )
    body = response.json()
    return not body["valid"]


@pytest.mark.parametrize(
    "case, event",
    [
        ("severity_id_out_of_range", {**_minimal(), "severity_id": 99}),
        ("missing_user_actor", _minimal()),
        ("missing_metadata", {**_minimal(), "actor": {"user": {"name": "jdoe"}}}),
    ],
)
def test_service_currently_accepts_contract_invalid_events(probe_client, case, event):
    assert not _service_rejects(probe_client, event)


@pytest.mark.parametrize(
    "case, event",
    [
        ("no_critical_fields", {"foo": "bar"}),
        ("missing_time", {"class_uid": 3002, "category_uid": 3}),
    ],
)
def test_service_rejects_only_missing_core_fields(probe_client, case, event):
    assert _service_rejects(probe_client, event)


def test_gap_is_sized_for_the_report(probe_client):
    # Every contract-invalid sample accepted above has a documented
    # contract-expected rejection (see CONTRACT_EXPECTS).  This is the
    # measurable wiring gap to be escalated to the service owner.
    assert set(CONTRACT_EXPECTS) == {
        "severity_id_out_of_range", "missing_user_actor", "missing_metadata",
    }
    assert len(CONTRACT_EXPECTS) >= 3