"""API tests for the Re-Validation Service (Task 3 endpoints)."""
import pytest
from fastapi.testclient import TestClient

import src.main as main
from src.service.history_store import RevalidationHistoryStore
from tests.samples import EVENT_ID, FIXED_EVENT, FLAWED_EVENT, VENDOR


@pytest.fixture()
def client(tmp_path, monkeypatch):
    store = RevalidationHistoryStore(str(tmp_path / "api.db"))
    monkeypatch.setattr(main, "store", store)
    return TestClient(main.app)


def test_home(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Re-Validation" in response.json()["message"]


def test_revalidate_first_run_uses_baseline(client):
    response = client.post(
        "/api/v2/revalidate",
        json={"event_id": EVENT_ID, "vendor": VENDOR, "normalized": FLAWED_EVENT},
    )
    assert response.status_code == 200
    run = response.json()
    assert run["verdict"] == "IMPROVED"
    assert run["confidence_before"] == 39.0
    assert run["confidence_after"] == 79.0


def test_revalidate_second_run_compares_to_last(client):
    for event in (FLAWED_EVENT, FIXED_EVENT):
        response = client.post(
            "/api/v2/revalidate",
            json={"event_id": EVENT_ID, "vendor": VENDOR, "normalized": event},
        )
        assert response.status_code == 200
    run = response.json()
    assert run["verdict"] == "IMPROVED"
    assert run["confidence_delta"] == 21.0
    assert "map.splunk.status_id" in run["improved_by"]
    assert run["before"]["normalized"]["status_id"] == 99


def test_revalidate_empty_normalized_rejected(client):
    response = client.post(
        "/api/v2/revalidate",
        json={"event_id": EVENT_ID, "vendor": VENDOR, "normalized": {}},
    )
    assert response.status_code == 400


def test_revalidate_compare_stateless(client):
    response = client.post(
        "/api/v2/revalidate/compare",
        json={"event_id": EVENT_ID, "vendor": VENDOR,
              "before": FLAWED_EVENT, "normalized": FIXED_EVENT},
    )
    assert response.status_code == 200
    run = response.json()
    assert run["verdict"] == "IMPROVED"
    assert run["confidence_delta"] == 21.0


def test_list_runs_and_get_by_id(client):
    client.post(
        "/api/v2/revalidate",
        json={"event_id": EVENT_ID, "vendor": VENDOR, "normalized": FLAWED_EVENT},
    )
    runs = client.get("/api/v2/revalidate/runs").json()
    assert len(runs) == 1
    run_id = runs[0]["run_id"]
    detail = client.get(f"/api/v2/revalidate/runs/{run_id}")
    assert detail.status_code == 200
    assert detail.json()["run_id"] == run_id


def test_get_missing_run_returns_404(client):
    response = client.get("/api/v2/revalidate/runs/does-not-exist")
    assert response.status_code == 404


def test_metrics_endpoint(client):
    client.post(
        "/api/v2/revalidate",
        json={"event_id": EVENT_ID, "vendor": VENDOR, "normalized": FIXED_EVENT},
    )
    metrics = client.get("/api/v2/revalidate/metrics").json()
    assert metrics["total_runs"] == 1
    assert metrics["improved_runs"] == 1
    assert metrics["top_rules_for_improvement"]


def test_rules_version_comparison_endpoint(client):
    for event in (FLAWED_EVENT, FIXED_EVENT):
        client.post(
            "/api/v2/revalidate",
            json={"event_id": EVENT_ID, "vendor": VENDOR, "normalized": event},
        )
    response = client.get(
        "/api/v2/revalidate/rules/compare",
        params={"v1": "1.0.0", "v2": "1.1.0"},
    )
    assert response.status_code == 200
    by_rule = {c["rule_id"]: c for c in response.json()}
    assert by_rule["map.splunk.base"]["removed_fields"] == ["map.splunk.base"]
    assert by_rule["map.splunk.status_id"]["added_fields"] == ["map.splunk.status_id"]