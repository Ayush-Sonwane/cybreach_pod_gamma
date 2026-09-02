"""Tests for the schedule configuration repository."""

import time

import pytest

from src.scheduling.repository import (
    DuplicateScheduleError,
    ScheduleRepository,
)


@pytest.fixture()
def repository(tmp_path):
    return ScheduleRepository(
        database_path=str(tmp_path / "schedules_test.db")
    )


def make_record(repository, **overrides):
    params = dict(
        name="nightly auth check",
        event_id="evt-123",
        interval_seconds=86400,
    )
    params.update(overrides)
    return repository.create(**params)


class TestCreateAndGet:

    def test_round_trip(self, repository):
        created = make_record(
            repository,
            request_template={"event_id": "evt-123", "event": {}},
        )
        schedule_id = created["schedule_id"]

        assert schedule_id.startswith("sched-")
        assert created["name"] == "nightly auth check"
        assert created["enabled"] is True
        assert created["is_running"] is False
        assert created["last_run_at"] is None
        assert created["next_run_at"] is None
        assert created["request_template"] == {
            "event_id": "evt-123",
            "event": {},
        }

        fetched = repository.get(schedule_id)
        assert fetched == created

    def test_get_missing_returns_none(self, repository):
        assert repository.get("sched-nope") is None

    def test_duplicate_id_raises(self, repository):
        make_record(repository, schedule_id="sched-dup")
        with pytest.raises(DuplicateScheduleError):
            make_record(
                repository,
                schedule_id="sched-dup",
                event_id="other",
            )

    def test_ids_are_unique(self, repository):
        first = make_record(repository)
        second = make_record(repository, event_id="evt-456")
        assert first["schedule_id"] != second["schedule_id"]


class TestList:

    def test_list_all_ordered_by_creation(self, repository):
        make_record(repository, name="first")
        make_record(repository, name="second", event_id="evt-2")

        schedules = repository.list()

        assert [s["name"] for s in schedules] == ["first", "second"]

    def test_list_enabled_filter(self, repository):
        active = make_record(repository)
        disabled = make_record(repository, event_id="evt-2")
        repository.update(disabled["schedule_id"], {"enabled": False})

        enabled_only = repository.list(enabled=True)

        assert [s["schedule_id"] for s in enabled_only] == [
            active["schedule_id"]
        ]

    def test_empty_list(self, repository):
        assert repository.list() == []


class TestUpdate:

    def test_update_fields(self, repository):
        record = make_record(repository)

        updated = repository.update(
            record["schedule_id"],
            {
                "interval_seconds": 3600,
                "missed_run_policy": "skip",
                "enabled": False,
            },
        )

        assert updated["interval_seconds"] == 3600
        assert updated["missed_run_policy"] == "skip"
        assert updated["enabled"] is False
        assert updated["updated_at"] >= record["created_at"]

    def test_update_request_template_to_none(self, repository):
        record = make_record(
            repository, request_template={"a": 1}
        )
        assert record["request_template"] == {"a": 1}

        updated = repository.update(
            record["schedule_id"], {"request_template": None}
        )
        assert updated["request_template"] is None

    def test_unknown_schedule_returns_none(self, repository):
        assert repository.update("sched-nope", {"enabled": False}) is None


class TestDelete:

    def test_delete_existing(self, repository):
        record = make_record(repository)
        assert repository.delete(record["schedule_id"]) is True
        assert repository.get(record["schedule_id"]) is None

    def test_delete_missing(self, repository):
        assert repository.delete("sched-nope") is False


class TestRunBookkeeping:

    def test_claim_and_release_cycle(self, repository):
        record = make_record(repository)
        schedule_id = record["schedule_id"]

        assert repository.claim_run(schedule_id) is True
        assert repository.get(schedule_id)["is_running"] is True
        assert repository.claim_run(schedule_id) is False

        now = time.time()
        repository.release_run(
            schedule_id,
            last_run_at=now,
            next_run_at=now + 3600,
        )

        released = repository.get(schedule_id)
        assert released["is_running"] is False
        assert released["last_run_at"] == now
        assert released["next_run_at"] == now + 3600

    def test_release_preserves_next_run_when_not_provided(self, repository):
        record = make_record(repository)
        schedule_id = record["schedule_id"]

        repository.update(schedule_id, {"next_run_at": 1000.0})
        repository.release_run(schedule_id, last_run_at=999.0)

        released = repository.get(schedule_id)
        assert released["last_run_at"] == 999.0
        assert released["next_run_at"] == 1000.0
