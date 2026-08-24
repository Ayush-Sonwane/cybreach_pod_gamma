import threading
import time
from datetime import datetime, timezone

import pytest

from src.core.config import SchedulerSettings
from src.repository import RevalidationRepository
from src.service.scheduler import (
    RevalidationRunner,
    RevalidationScheduler,
    SchedulerBusyError,
)


class FakeClock:
    def __init__(self, start=100.0, step=0.25):
        self.now = start
        self.step = step

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


class FakeWallClock:
    def __init__(self, start_epoch=1_770_000_000):
        self._epoch = start_epoch

    def __call__(self):
        stamp = datetime.fromtimestamp(self._epoch, tz=timezone.utc).isoformat()
        self._epoch += 1
        return stamp


class StaticRunner:
    def __init__(self, result=None, exc=None):
        self.result = result or {
            "checked_count": 3,
            "valid_count": 2,
            "invalid_count": 1,
        }
        self.exc = exc
        self.calls = 0

    def run(self):
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return dict(self.result)


class BlockingRunner:
    def __init__(self):
        self.started_event = threading.Event()
        self.release_event = threading.Event()
        self.calls = 0

    def run(self):
        self.calls += 1
        self.started_event.set()
        assert self.release_event.wait(timeout=10), "runner never released"
        return {"checked_count": 1, "valid_count": 1, "invalid_count": 0}


class AlwaysFailingRepository:
    def list_runs(self):
        return []

    def start_scheduler_history(self, **kwargs):
        raise RuntimeError("disk full")

    def finish_scheduler_history(self, **kwargs):
        raise RuntimeError("disk full")

    def record_skipped_scheduler_tick(self, **kwargs):
        raise RuntimeError("disk full")


@pytest.fixture()
def repository(tmp_path):
    return RevalidationRepository(database_path=str(tmp_path / "reval.db"))


@pytest.fixture()
def seed_events(repository):
    valid_event = {"class_uid": 1002, "category_uid": 2, "time": 1700000000}
    for index in range(2):
        repository.save(
            re_run_id=f"rerun-{index}",
            event_id=f"evt-{index}",
            idempotency_key=f"key-{index}",
            original_event={"time": 1},
            updated_event=dict(valid_event),
            valid=True,
            errors=[],
        )
    repository.save(
        re_run_id="rerun-bad",
        event_id="evt-bad",
        idempotency_key="key-bad",
        original_event={"time": 1},
        updated_event={"class_uid": None, "category_uid": 2},
        valid=False,
        errors=["Missing mandatory OCSF field: 'time'"],
    )
    return repository


def make_scheduler(settings=None, runner=None, repository=None, clock=None, wall=None):
    return RevalidationScheduler(
        settings=settings or SchedulerSettings(),
        runner=runner or StaticRunner(),
        repository=repository,
        time_source=clock or FakeClock(),
        wall_clock=wall or FakeWallClock(),
    )


def _simple_validator(event):
    missing = [
        field
        for field in ("class_uid", "category_uid", "time")
        if event.get(field) is None
    ]
    return (len(missing) == 0, missing)


class TestRevalidationRunner:
    def test_counts_valid_and_invalid_stored_events(self, seed_events):
        runner = RevalidationRunner(repository=seed_events, validator=_simple_validator)
        assert runner.run() == {
            "checked_count": 3,
            "valid_count": 2,
            "invalid_count": 1,
        }

    def test_validator_exception_isolated_per_event(self, seed_events):
        def exploding_validator(_event):
            raise RuntimeError("boom")

        runner = RevalidationRunner(
            repository=seed_events, validator=exploding_validator
        )
        result = runner.run()
        assert result["checked_count"] == 3
        assert result["invalid_count"] == 3


class TestRunOnceSinglePath:
    def test_manual_run_completes_and_records_history(self, repository):
        scheduler = make_scheduler(repository=repository)
        snapshot = scheduler.run_once("manual")

        assert snapshot["status"] == "completed"
        assert snapshot["trigger"] == "manual"
        assert snapshot["checked_count"] == 3
        assert snapshot["valid_count"] == 2
        assert snapshot["invalid_count"] == 1

        history = repository.list_scheduler_history(limit=5)
        assert len(history) == 1
        row = history[0]
        assert row["run_id"] == snapshot["run_id"]
        assert row["status"] == "completed"
        assert row["error"] is None
        assert row["started_at"] is not None
        assert row["finished_at"] is not None

    def test_duration_uses_monotonic_clock(self, repository):
        clock = FakeClock(start=10.0, step=0.5)
        scheduler = make_scheduler(repository=repository, clock=clock)
        snapshot = scheduler.run_once("manual")
        assert snapshot["duration_ms"] == 500.0

    def test_timestamps_are_utc_iso(self, repository):
        scheduler = make_scheduler(repository=repository)
        snapshot = scheduler.run_once("manual")
        parsed = datetime.fromisoformat(snapshot["started_at"])
        assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)

    def test_invalid_trigger_rejected(self, repository):
        scheduler = make_scheduler(repository=repository)
        with pytest.raises(ValueError, match="trigger"):
            scheduler.run_once("auto")

    def test_last_run_snapshot_updated(self, repository):
        scheduler = make_scheduler(repository=repository)
        snapshot = scheduler.run_once("manual")
        assert scheduler.last_run()["run_id"] == snapshot["run_id"]
        assert scheduler.counters()["runs_started"] == 1


class TestFailureAsData:
    def test_runner_failure_recorded_not_raised(self, repository):
        runner = StaticRunner(exc=ValueError("db exploded"))
        scheduler = make_scheduler(repository=repository, runner=runner)

        snapshot = scheduler.run_once("manual")

        assert snapshot["status"] == "failed"
        assert "ValueError" in snapshot["error"]
        row = repository.list_scheduler_history(limit=5)[0]
        assert row["status"] == "failed"
        assert "ValueError" in row["error"]

    def test_failed_runs_counted_in_runs_started(self, repository):
        runner = StaticRunner(exc=ValueError("x"))
        scheduler = make_scheduler(repository=repository, runner=runner)
        scheduler.run_once("manual")
        assert scheduler.counters()["runs_started"] == 1


class TestExecutionLock:
    def test_manual_while_active_raises_busy_error(self, repository):
        blocking = BlockingRunner()
        scheduler = make_scheduler(repository=repository, runner=blocking)
        worker = threading.Thread(target=scheduler.run_once, args=("manual",))
        worker.start()
        try:
            assert blocking.started_event.wait(timeout=5)
            with pytest.raises(SchedulerBusyError):
                scheduler.run_once("manual")
        finally:
            blocking.release_event.set()
            worker.join(timeout=5)
        assert worker.is_alive() is False

    def test_scheduled_tick_skips_when_active_and_records_row(self, repository):
        blocking = BlockingRunner()
        scheduler = make_scheduler(repository=repository, runner=blocking)
        worker = threading.Thread(target=scheduler.run_once, args=("manual",))
        worker.start()
        try:
            assert blocking.started_event.wait(timeout=5)

            result = scheduler.run_once(trigger="scheduled")

            assert result["status"] == "skipped"
            rows = repository.list_scheduler_history(limit=10)
            skipped = [row for row in rows if row["trigger"] == "skipped_tick"]
            assert len(skipped) == 1
            assert skipped[0]["finished_at"] is not None
            assert scheduler.counters()["skipped_ticks"] == 1
        finally:
            blocking.release_event.set()
            worker.join(timeout=5)

        # The active run was unaffected by the skip.
        assert scheduler.last_run()["status"] == "completed"


class TestLifecycle:
    def test_double_start_is_guarded_single_thread(self, repository):
        blocking = BlockingRunner()
        settings = SchedulerSettings(enabled=True, interval_seconds=3600)
        scheduler = make_scheduler(
            settings=settings, runner=blocking, repository=repository
        )
        try:
            assert scheduler.start() is True
            assert scheduler.is_running()
            assert scheduler.start() is False
            assert scheduler.start() is False
        finally:
            blocking.release_event.set()
        scheduler.stop(timeout=5)
        assert scheduler.is_running() is False

    def test_stop_interrupts_sleep_promptly(self, repository):
        settings = SchedulerSettings(interval_seconds=3600)
        scheduler = make_scheduler(repository=repository, settings=settings)
        scheduler.start()
        started = time.perf_counter()
        scheduler.stop(timeout=5)
        elapsed = time.perf_counter() - started
        assert elapsed < 2.0
        assert scheduler.is_running() is False

    def test_restart_after_stop_creates_fresh_thread(self, repository):
        settings = SchedulerSettings(interval_seconds=3600)
        scheduler = make_scheduler(repository=repository, settings=settings)
        scheduler.start()
        scheduler.stop(timeout=5)
        assert scheduler.start() is True
        scheduler.stop(timeout=5)
        assert scheduler.is_running() is False

    def test_fixed_delay_executes_multiple_runs(self, repository):
        runner = StaticRunner()
        settings = SchedulerSettings(interval_seconds=0.05)
        scheduler = make_scheduler(
            settings=settings, runner=runner, repository=repository
        )
        scheduler.start()
        deadline = time.time() + 5
        while runner.calls < 3 and time.time() < deadline:
            time.sleep(0.01)
        scheduler.stop(timeout=5)
        assert runner.calls >= 3
        assert scheduler.is_running() is False

    def test_loop_survives_repeated_infrastructure_errors(self):
        runner = StaticRunner()
        settings = SchedulerSettings(interval_seconds=0.05)
        scheduler = RevalidationScheduler(
            settings=settings,
            runner=runner,
            repository=AlwaysFailingRepository(),
            wall_clock=FakeWallClock(),
        )
        scheduler.start()
        deadline = time.time() + 5
        while scheduler.counters()["runs_started"] < 2 and time.time() < deadline:
            time.sleep(0.01)
        scheduler.stop(timeout=5)
        assert scheduler.counters()["runs_started"] >= 2


class TestConcurrency:
    def test_parallel_manual_runs_serialize_exactly_once(self, seed_events):
        scheduler = make_scheduler(repository=seed_events)
        results = []
        busy_count = [0]
        lock = threading.Lock()

        def worker():
            try:
                snapshot = scheduler.run_once("manual")
                with lock:
                    results.append(snapshot)
            except SchedulerBusyError:
                with lock:
                    busy_count[0] += 1

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        manual_rows = [
            row
            for row in seed_events.list_scheduler_history(limit=20)
            if row["trigger"] == "manual"
        ]
        assert len(results) + busy_count[0] == 8
        assert len(results) == len(manual_rows)
