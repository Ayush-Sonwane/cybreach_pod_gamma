"""
Re-Validation endpoint QA: delta report accuracy over HTTP, idempotency
matrix, and error handling.  Uses a per-test temp repository swapped into
src.main (same pattern as the existing API tests).
"""
import pytest
from fastapi.testclient import TestClient

import src.main as main_module
from src.repository import RevalidationRepository
from src.service.scheduler import RevalidationRunner, RevalidationScheduler
from src.core.config import SchedulerSettings


def _event(severity=1, time=1700000000, ip="10.0.0.1"):
    return {
        "class_uid": 3002, "category_uid": 3, "time": time,
        "severity_id": severity,
        "src_endpoint": {"ip": ip, "port": 443},
    }


ORIGINAL = _event(severity=1)
UPDATED = _event(severity=2, time=1700000001, ip="10.0.0.9")


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    repository = RevalidationRepository(database_path=str(tmp_path / "qa.db"))
    runner = RevalidationRunner(repository=repository, validator=main_module.validate_ocsf_event)
    scheduler = RevalidationScheduler(settings=SchedulerSettings(), runner=runner, repository=repository)
    monkeypatch.setattr(main_module, "repository", repository)
    monkeypatch.setattr(main_module, "scheduler", scheduler)
    with TestClient(main_module.app) as client:
        yield client, repository


def _post(client, key, original=None, updated=None, event_id="evt-qa"):
    return client.post(
        "/api/v2/revalidate",
        headers={"Idempotency-Key": key},
        json={
            "event_id": event_id,
            "original_event": original if original is not None else ORIGINAL,
            "event": updated if updated is not None else UPDATED,
        },
    )


def _delta(client, re_run_id):
    return client.get(f"/api/v2/revalidate/{re_run_id}/delta")


# --------------------------------------------------------------------------- #
# Delta report accuracy over HTTP
# --------------------------------------------------------------------------- #

class TestDeltaReportAccuracy:
    def test_delta_matches_ground_truth(self, api_client):
        client, _ = api_client
        response = _post(client, "gt-1")
        assert response.status_code == 200
        re_run_id = response.json()["re_run_id"]

        delta = _delta(client, re_run_id)
        assert delta.status_code == 200
        assert delta.json()["changes"] == [
            {"field": "severity_id", "before": 1, "after": 2, "change_type": "data"},
            {"field": "src_endpoint.ip", "before": "10.0.0.1",
             "after": "10.0.0.9", "change_type": "data"},
            {"field": "time", "before": 1700000000,
             "after": 1700000001, "change_type": "data"},
        ]

    def test_identical_events_produce_empty_delta(self, api_client):
        client, _ = api_client
        response = _post(client, "gt-2", updated=ORIGINAL)
        delta = _delta(client, response.json()["re_run_id"])
        assert delta.json()["changes"] == []

    def test_delta_is_immutable_across_repeated_reads(self, api_client):
        client, _ = api_client
        re_run_id = _post(client, "gt-3").json()["re_run_id"]
        first = _delta(client, re_run_id).json()
        second = _delta(client, re_run_id).json()
        assert first == second

    def test_delta_response_shape(self, api_client):
        client, _ = api_client
        body = _post(client, "gt-4").json()
        delta = _delta(client, body["re_run_id"]).json()
        assert delta["re_run_id"] == body["re_run_id"]
        assert delta["event_id"] == "evt-qa"
        assert isinstance(delta["changes"], list)
        for entry in delta["changes"]:
            assert set(entry) == {"field", "before", "after", "change_type"}


# --------------------------------------------------------------------------- #
# Idempotency matrix
# --------------------------------------------------------------------------- #

class TestIdempotency:
    def test_same_key_same_request_returns_existing_run(self, api_client):
        client, _ = api_client
        first = _post(client, "idem-1").json()
        second = _post(client, "idem-1").json()
        assert first["status"] == "completed"
        assert first["idempotent"] is False
        assert second["status"] == "already_processed"
        assert second["idempotent"] is True
        assert second["re_run_id"] == first["re_run_id"]
        assert second["valid"] == first["valid"]
        assert second["errors"] == first["errors"]

    def test_replayed_delta_is_identical(self, api_client):
        client, _ = api_client
        first = _post(client, "idem-2").json()
        second = _post(client, "idem-2").json()
        assert _delta(client, first["re_run_id"]).json() == _delta(client, second["re_run_id"]).json()

    def test_same_key_different_request_conflicts(self, api_client):
        client, _ = api_client
        _post(client, "idem-3")
        conflict = _post(client, "idem-3", updated=_event(time=9999999999))
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "IDEMPOTENCY_KEY_CONFLICT"

    def test_missing_header_is_rejected(self, api_client):
        client, _ = api_client
        response = client.post(
            "/api/v2/revalidate",
            json={"event_id": "evt", "original_event": {}, "event": {"time": 1}},
        )
        assert response.status_code == 422

    def test_empty_key_is_rejected(self, api_client):
        client, _ = api_client
        response = _post(client, "   ")
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "INVALID_IDEMPOTENCY_KEY"

    def test_oversized_key_is_rejected(self, api_client):
        client, _ = api_client
        response = _post(client, "k" * 256)
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "INVALID_IDEMPOTENCY_KEY"

    def test_max_length_key_is_accepted(self, api_client):
        client, _ = api_client
        response = _post(client, "k" * 255)
        assert response.status_code == 200
        assert response.json()["idempotent"] is False


# --------------------------------------------------------------------------- #
# Event validation behavior (current simplified validator, documented as-is)
# --------------------------------------------------------------------------- #

class TestEventValidation:
    def test_invalid_event_is_reported_but_not_rejected(self, api_client):
        client, _ = api_client
        response = _post(client, "val-1", updated={"time": 1})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "completed"
        assert body["valid"] is False
        assert any("class_uid" in e for e in body["errors"])

    def test_valid_event_returns_valid_true(self, api_client):
        client, _ = api_client
        body = _post(client, "val-2").json()
        assert body["valid"] is True
        assert body["errors"] == []


# --------------------------------------------------------------------------- #
# Error handling on the delta endpoint
# --------------------------------------------------------------------------- #

class TestDeltaEndpointErrors:
    def test_unknown_re_run_returns_404(self, api_client):
        client, _ = api_client
        response = _delta(client, "rerun-does-not-exist")
        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "RE_RUN_NOT_FOUND"

    def test_blank_re_run_id_returns_400(self, api_client):
        client, _ = api_client
        response = client.get("/api/v2/revalidate/%20%20/delta")
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "INVALID_RE_RUN_ID"

    def test_response_registration_shape(self, api_client):
        client, _ = api_client
        body = _post(client, "shape-1").json()
        assert body["re_run_id"].startswith("rerun-")
        assert body["event_id"] == "evt-qa"
        assert body["status"] == "completed"
        assert body["idempotent"] is False