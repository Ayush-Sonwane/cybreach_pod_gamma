import threading

import pytest
from fastapi.testclient import TestClient

import src.main as main_module
from src.core.config import SchedulerSettings
from src.repository import RevalidationRepository
from src.service.scheduler import RevalidationRunner, RevalidationScheduler

VALID_EVENT = {
    "class_uid": 1002,
    "category_uid": 2,
    "time": 1700000000,
}


class BlockingRunner:
    def __init__(self):
        self.started_event = threading.Event()
        self.release_event = threading.Event()

    def run(self):
        self.started_event.set()
        assert self.release_event.wait(timeout=10), "runner never released"
        return {"checked_count": 0, "valid_count": 0, "invalid_count": 0}


def post_event(client, key):
    return client.post(
        "/api/v2/revalidate",
        headers={"Idempotency-Key": key},
        json={
            "event_id": "evt-1",
            "original_event": {"time": 1},
            "event": dict(VALID_EVENT),
        },
    )


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    repository = RevalidationRepository(database_path=str(tmp_path / "api.db"))
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


@pytest.fixture()
def busy_api_client(tmp_path, monkeypatch):
    repository = RevalidationRepository(database_path=str(tmp_path / "busy.db"))
    scheduler = RevalidationScheduler(
        settings=SchedulerSettings(),
        runner=BlockingRunner(),
        repository=repository,
    )
    monkeypatch.setattr(main_module, "repository", repository)
    monkeypatch.setattr(main_module, "scheduler", scheduler)

    with TestClient(main_module.app) as client:
        yield client, scheduler


class TestSchedulerStatus:
    def test_default_disabled_shape(self, api_client):
        client, scheduler, repository = api_client

        response = client.get("/api/v2/revalidate/scheduler/status")

        assert response.status_code == 200
        body = response.json()
        assert body["settings"] == {"enabled": False, "interval_seconds": 300}
        assert body["scheduler_running"] is False
        assert body["runs_started"] == 0
        assert body["skipped_ticks"] == 0
        assert body["last_run"] is None
        assert body["recent_runs"] == []


class TestRunNow:
    def test_run_now_executes_single_pass(self, api_client):
        client, scheduler, repository = api_client

        seeded = post_event(client, "key-1")
        assert seeded.status_code == 200

        response = client.post("/api/v2/revalidate/scheduler/run-now")

        assert response.status_code == 200
        body = response.json()
        assert body["trigger"] == "manual"
        assert body["status"] == "completed"
        assert body["checked_count"] == 1
        assert body["valid_count"] == 1
        assert body["invalid_count"] == 0
        assert body["error"] is None

        status = client.get("/api/v2/revalidate/scheduler/status").json()
        assert status["runs_started"] == 1
        assert status["last_run"]["run_id"] == body["run_id"]
        assert len(status["recent_runs"]) == 1

    def test_runner_failure_returns_200_with_failed_status(self, tmp_path, monkeypatch):
        class ExplodingRunner:
            def run(self):
                raise ValueError("db exploded")

        repository = RevalidationRepository(database_path=str(tmp_path / "fail.db"))
        scheduler = RevalidationScheduler(
            settings=SchedulerSettings(),
            runner=ExplodingRunner(),
            repository=repository,
        )
        monkeypatch.setattr(main_module, "repository", repository)
        monkeypatch.setattr(main_module, "scheduler", scheduler)

        with TestClient(main_module.app) as client:
            response = client.post("/api/v2/revalidate/scheduler/run-now")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert "ValueError" in body["error"]

    def test_run_now_conflict_returns_409_while_active(self, busy_api_client):
        client, scheduler = busy_api_client

        worker = threading.Thread(target=scheduler.run_once, args=("manual",))
        worker.start()
        try:
            assert scheduler._runner.started_event.wait(timeout=5)

            response = client.post("/api/v2/revalidate/scheduler/run-now")

            assert response.status_code == 409
            detail = response.json()["detail"]
            assert detail["code"] == "SCHEDULER_RUN_IN_PROGRESS"
        finally:
            scheduler._runner.release_event.set()
            worker.join(timeout=5)


class TestExistingEndpointsUnaffected:
    def test_health_and_revalidate_round_trip(self, api_client):
        client, _scheduler, _repository = api_client

        health = client.get("/health")
        assert health.status_code == 200
        assert health.json() == {"status": "healthy"}

        first = post_event(client, "key-regression")
        assert first.status_code == 200
        assert first.json()["valid"] is True
        assert first.json()["idempotent"] is False

        second = post_event(client, "key-regression")
        assert second.status_code == 200
        assert second.json()["status"] == "already_processed"
        assert second.json()["idempotent"] is True

    def test_delta_endpoint_still_works(self, api_client):
        client, _scheduler, _repository = api_client

        created = post_event(client, "key-delta").json()

        delta = client.get(f"/api/v2/revalidate/{created['re_run_id']}/delta")

        assert delta.status_code == 200
        changes = delta.json()["changes"]
        assert len(changes) >= 1
