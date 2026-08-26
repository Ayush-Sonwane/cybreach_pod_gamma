"""Tests for PUT /api/v2/revalidate/scheduler/config — task #5 seam.

Uses the same monkeypatch pattern as test_scheduler_api.py to
isolate the endpoint from the module-level scheduler instance.
"""

import pytest
from fastapi.testclient import TestClient

import src.main as main_module
from src.core.config import SchedulerSettings
from src.repository import RevalidationRepository
from src.service.scheduler import RevalidationRunner, RevalidationScheduler


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    repository = RevalidationRepository(
        database_path=str(tmp_path / "config_test.db")
    )
    runner = RevalidationRunner(
        repository=repository,
        validator=main_module.validate_ocsf_event,
    )
    scheduler = RevalidationScheduler(
        settings=SchedulerSettings(),
        runner=runner,
        repository=repository,
    )
    monkeypatch.setattr(main_module, "repository", repository)
    monkeypatch.setattr(main_module, "scheduler", scheduler)

    with TestClient(main_module.app) as client:
        yield client, scheduler, repository


def put_config(client, body):
    return client.put("/api/v2/revalidate/scheduler/config", json=body)


def get_status(client):
    return client.get("/api/v2/revalidate/scheduler/status")


class TestUpdateSchedulerConfig:

    def test_updates_interval_seconds(self, api_client):
        client, scheduler, _ = api_client

        response = put_config(client, {
            "enabled": False,
            "interval_seconds": 600,
        })

        assert response.status_code == 200
        body = response.json()
        assert body["enabled"] is False
        assert body["interval_seconds"] == 600
        assert scheduler.settings.interval_seconds == 600

    def test_updates_enabled(self, api_client):
        client, scheduler, _ = api_client

        response = put_config(client, {
            "enabled": True,
            "interval_seconds": 300,
        })

        assert response.status_code == 200
        body = response.json()
        assert body["enabled"] is True
        assert scheduler.settings.enabled is True

        status = get_status(client).json()
        assert status["settings"]["enabled"] is True

    def test_enable_starts_scheduler(self, api_client):
        client, scheduler, _ = api_client

        assert scheduler.is_running() is False

        put_config(client, {"enabled": True, "interval_seconds": 300})

        assert scheduler.is_running() is True

        scheduler.stop()

    def test_disable_stops_scheduler(self, api_client):
        client, scheduler, _ = api_client

        put_config(client, {"enabled": True, "interval_seconds": 300})
        assert scheduler.is_running() is True

        put_config(client, {"enabled": False, "interval_seconds": 300})
        assert scheduler.is_running() is False

    def test_interval_change_while_running_takes_effect(self, api_client):
        client, scheduler, _ = api_client

        put_config(client, {"enabled": True, "interval_seconds": 300})
        put_config(client, {"enabled": True, "interval_seconds": 60})

        assert scheduler.settings.interval_seconds == 60
        assert scheduler.is_running() is True

        scheduler.stop()

    def test_invalid_interval_rejected(self, api_client):
        client, _, _ = api_client

        response = put_config(client, {
            "enabled": True,
            "interval_seconds": 0,
        })

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["code"] == "INVALID_SCHEDULER_CONFIG"

    def test_negative_interval_rejected(self, api_client):
        client, _, _ = api_client

        response = put_config(client, {
            "enabled": False,
            "interval_seconds": -5,
        })

        assert response.status_code == 422

    def test_minimal_valid_interval(self, api_client):
        client, scheduler, _ = api_client

        response = put_config(client, {
            "enabled": False,
            "interval_seconds": 1,
        })

        assert response.status_code == 200
        assert scheduler.settings.interval_seconds == 1

    def test_reflected_in_status_endpoint(self, api_client):
        client, _, _ = api_client

        put_config(client, {"enabled": True, "interval_seconds": 120})

        status = get_status(client).json()
        assert status["settings"]["enabled"] is True
        assert status["settings"]["interval_seconds"] == 120

    def test_preserves_enabled_when_only_interval_changes(self, api_client):
        client, scheduler, _ = api_client

        put_config(client, {"enabled": True, "interval_seconds": 300})
        assert scheduler.settings.enabled is True

        put_config(client, {"enabled": False, "interval_seconds": 90})
        assert scheduler.settings.enabled is False
        assert scheduler.settings.interval_seconds == 90
