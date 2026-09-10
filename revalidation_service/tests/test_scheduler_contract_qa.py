"""
Scheduler contract QA (SCHEDULER_CONTRACT.md clauses 1-11 short-form).

Focus: the runner consumes the STORED updated_event (the re-validation input
source), failures are data not exceptions, history counts reconcile with the
actual stored rows, run-now works while scheduling is disabled, and the
interval-configuration seam rejects invalid values.
"""
import pytest

from src.repository import RevalidationRepository
from src.service.scheduler import RevalidationRunner, RevalidationScheduler
from src.core.config import SchedulerSettings
from src.scheduling.api import router


def _stored_event(time):
    return {"class_uid": 3002, "category_uid": 3, "time": time}


class RecordingValidator:
    def __init__(self):
        self.calls = []

    def __call__(self, event):
        self.calls.append(event)
        return True, []


@pytest.fixture()
def repository(tmp_path):
    return RevalidationRepository(database_path=str(tmp_path / "scheduler_qa.db"))


def _seed(repository, n=3):
    for i in range(n):
        repository.save(
            re_run_id=f"rerun-sched-{i}", event_id=f"evt-{i}",
            idempotency_key=f"key-sched-{i}",
            original_event=_stored_event(i),
            updated_event=_stored_event(i + 10),
            valid=True, errors=[],
        )


class TestRunnerInputSource:
    def test_runner_consumes_stored_updated_event(self, repository):
        _seed(repository)
        recording = RecordingValidator()
        RevalidationRunner(repository=repository, validator=recording).run()
        # Exactly the stored updated_events, in rowid order, no originals.
        assert recording.calls == [_stored_event(10), _stored_event(11), _stored_event(12)]

    def test_runner_exception_is_isolated_and_counted_invalid(self, repository):
        _seed(repository, n=3)
        calls = []

        def exploding(event):
            calls.append(event)
            if event["time"] == 12:
                raise RuntimeError("boom")
            return True, []

        counts = RevalidationRunner(repository=repository, validator=exploding).run()
        assert counts == {"checked_count": 3, "valid_count": 2, "invalid_count": 1}
        assert len(calls) == 3


class TestHistoryReconciliation:
    def test_run_history_counts_reconcile_with_stored_rows(self, repository):
        _seed(repository, n=3)
        scheduler = RevalidationScheduler(
            settings=SchedulerSettings(),
            runner=RevalidationRunner(repository=repository, validator=lambda e: (True, [])),
            repository=repository,
        )
        snapshot = scheduler.run_once("manual")
        assert snapshot["status"] == "completed"
        assert snapshot["trigger"] == "manual"
        assert snapshot["checked_count"] == 3
        assert snapshot["valid_count"] == 3
        assert snapshot["invalid_count"] == 0
        assert snapshot["duration_ms"] >= 0
        assert snapshot["started_at"] and snapshot["finished_at"]

        history = repository.list_scheduler_history(limit=5)
        assert len(history) == 1
        row = history[0]
        assert row["run_id"] == snapshot["run_id"]
        assert row["status"] == "completed"
        assert row["checked_count"] == 3
        assert row["valid_count"] == 3
        assert row["invalid_count"] == 0

    def test_per_event_exception_is_counted_not_fatal(self, repository):
        # Clause 5 + runner isolation: an event that throws is counted as
        # invalid; the overall run still completes.
        _seed(repository, n=1)

        def exploding(event):
            raise ValueError("boom")

        scheduler = RevalidationScheduler(
            settings=SchedulerSettings(),
            runner=RevalidationRunner(repository=repository, validator=exploding),
            repository=repository,
        )
        snapshot = scheduler.run_once("manual")
        assert snapshot["status"] == "completed"
        assert snapshot["invalid_count"] == 1
        assert snapshot["checked_count"] == 1

    def test_run_level_failure_is_recorded_not_raised(self, repository):
        _seed(repository, n=1)

        class ExplodingRunner:
            def run(self):
                raise ValueError("db exploded")

        scheduler = RevalidationScheduler(
            settings=SchedulerSettings(),
            runner=ExplodingRunner(),
            repository=repository,
        )
        snapshot = scheduler.run_once("manual")
        assert snapshot["status"] == "failed"
        assert "ValueError" in snapshot["error"]
        history = repository.list_scheduler_history(limit=1)
        assert history[0]["status"] == "failed"


class TestEnabledFlag:
    def test_run_now_available_while_scheduling_disabled(self, repository):
        _seed(repository, n=1)
        scheduler = RevalidationScheduler(
            settings=SchedulerSettings(enabled=False),
            runner=RevalidationRunner(repository=repository, validator=lambda e: (True, [])),
            repository=repository,
        )
        assert scheduler.is_running() is False
        snapshot = scheduler.run_once("manual")
        assert snapshot["status"] == "completed"
        assert snapshot["checked_count"] == 1

    def test_scheduled_trigger_records_trigger_kind(self, repository):
        scheduler = RevalidationScheduler(
            settings=SchedulerSettings(enabled=False),
            runner=RevalidationRunner(repository=repository, validator=lambda e: (True, [])),
            repository=repository,
        )
        snapshot = scheduler.run_once("scheduled")
        assert snapshot["trigger"] == "scheduled"
        assert repository.list_scheduler_history(limit=1)[0]["trigger"] == "scheduled"


class TestConfigSeam:
    def _client(self, tmp_path, monkeypatch):
        import src.main as main_module
        from fastapi.testclient import TestClient

        repository = RevalidationRepository(database_path=str(tmp_path / "seam.db"))
        scheduler = RevalidationScheduler(
            settings=SchedulerSettings(),
            runner=RevalidationRunner(repository=repository, validator=main_module.validate_ocsf_event),
            repository=repository,
        )
        monkeypatch.setattr(main_module, "repository", repository)
        monkeypatch.setattr(main_module, "scheduler", scheduler)
        return TestClient(main_module.app), scheduler

    def test_interval_validation_rejects_invalid_values(self, tmp_path, monkeypatch):
        client, _ = self._client(tmp_path, monkeypatch)
        # Handler-level validation (values the schema accepts but the app rejects).
        for bad in (0, -5):
            response = client.put(
                "/api/v2/revalidate/scheduler/config",
                json={"enabled": False, "interval_seconds": bad},
            )
            assert response.status_code == 422
            assert response.json()["detail"]["code"] == "INVALID_SCHEDULER_CONFIG"
        # Schema-level rejection: a fractional interval fails pydantic coercion.
        fractional = client.put(
            "/api/v2/revalidate/scheduler/config",
            json={"enabled": False, "interval_seconds": 0.5},
        )
        assert fractional.status_code == 422

    def test_interval_validation_accepts_valid_value(self, tmp_path, monkeypatch):
        client, scheduler = self._client(tmp_path, monkeypatch)
        response = client.put(
            "/api/v2/revalidate/scheduler/config",
            json={"enabled": False, "interval_seconds": 60},
        )
        assert response.status_code == 200
        assert response.json() == {"enabled": False, "interval_seconds": 60}
        assert scheduler.settings.interval_seconds == 60


def test_contract_doc_exists():
    import os
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert os.path.exists(os.path.join(here, "SCHEDULER_CONTRACT.md"))


def test_scheduler_router_registered_on_app():
    import src.main as main_module
    names = {
        path
        for route in main_module.app.routes
        for path in [getattr(route, "path", None)]
        if path
    }
    assert "/api/v2/revalidate/scheduler/status" in names
    assert "/api/v2/revalidate/scheduler/run-now" in names
    assert "/api/v2/revalidate/scheduler/config" in names
    assert router is not None