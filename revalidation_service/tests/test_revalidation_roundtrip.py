"""
Re-validation repository round-trip fidelity (QA).

Verifies that before/after events survive the SQLite JSON round-trip
byte-identically: a delta computed from what was SUBMITTED must equal a delta
computed from what is READ BACK.  Guards against silent storage corruption
(key-order drift, int->float coercion, NaN, truncation).
"""
import sqlite3

from src.repository import RevalidationRepository


def _db(tmp_path):
    return RevalidationRepository(database_path=str(tmp_path / "roundtrip.db"))


EVENT_A = {
    "class_uid": 3002, "category_uid": 3, "time": 1700000000,
    "severity_id": 1,
    "src_endpoint": {"ip": "10.0.0.1", "port": 443},
    "metadata": {"provenance": [{"ocsf_field": "time", "raw_field": "@timestamp"}]},
}

EVENT_B = {
    "class_uid": 3002, "category_uid": 3, "time": 1700000001,
    "severity_id": 2,
    "src_endpoint": {"ip": "10.0.0.9", "port": 443},
    "metadata": {"provenance": [{"ocsf_field": "time", "raw_field": "@timestamp"}]},
}


def test_events_round_trip_byte_identical(tmp_path):
    repo = _db(tmp_path)
    repo.save(
        re_run_id="rerun-qa1", event_id="evt-1", idempotency_key="key-a",
        original_event=EVENT_A, updated_event=EVENT_B,
        valid=True, errors=[],
    )
    row = repo.get_by_id("rerun-qa1")
    assert row["original_event"] == EVENT_A
    assert row["updated_event"] == EVENT_B
    assert row["event_id"] == "evt-1"
    assert row["valid"] is True
    assert row["errors"] == []


def test_delta_identical_before_and_after_persistence(tmp_path):
    from src.service.delta_engine import DeltaEngine

    repo = _db(tmp_path)
    direct = DeltaEngine.calculate(EVENT_A, EVENT_B)

    repo.save(
        re_run_id="rerun-qa2", event_id="evt-1", idempotency_key="key-b",
        original_event=EVENT_A, updated_event=EVENT_B,
        valid=True, errors=[],
    )
    row = repo.get_by_id("rerun-qa2")
    from_storage = DeltaEngine.calculate(row["original_event"], row["updated_event"])

    assert from_storage == direct


def test_int_and_float_types_survive_round_trip(tmp_path):
    # In particular a float-valued field that happens to be integral
    # (e.g. 1.5 -> 1.5) and an integer field must not be coerced.
    original = {"time": 1700000000, "score": 0.5, "big": 2 ** 63}
    updated = {"time": 1700000000, "score": 0.75, "big": 2 ** 63}
    repo = _db(tmp_path)
    repo.save(
        re_run_id="rerun-qa3", event_id="evt-3", idempotency_key="key-c",
        original_event=original, updated_event=updated, valid=True, errors=[],
    )
    row = repo.get_by_id("rerun-qa3")
    assert row["original_event"] == {"time": 1700000000, "score": 0.5, "big": 2 ** 63}
    assert row["updated_event"]["score"] == 0.75
    assert type(row["original_event"]["score"]) is float
    assert type(row["original_event"]["time"]) is int
    assert type(row["original_event"]["big"]) is int


def test_idempotency_lookup_round_trip(tmp_path):
    repo = _db(tmp_path)
    repo.save(
        re_run_id="rerun-qa4", event_id="evt-4", idempotency_key="key-d",
        original_event=EVENT_A, updated_event=EVENT_B,
        valid=False, errors=["Missing mandatory OCSF field: 'time'"],
    )
    row = repo.get_by_idempotency_key("key-d")
    assert row["re_run_id"] == "rerun-qa4"
    assert row["original_event"] == EVENT_A
    assert row["request_hash"] == repo.build_request_hash(
        event_id="evt-4", original_event=EVENT_A, updated_event=EVENT_B
    )


def test_request_hash_stable_under_key_reordering():
    a = RevalidationRepository.build_request_hash(
        event_id="e", original_event={"a": 1, "b": {"c": 2}}, updated_event={"x": 1}
    )
    b = RevalidationRepository.build_request_hash(
        event_id="e", original_event={"b": {"c": 2}, "a": 1}, updated_event={"x": 1}
    )
    assert a == b


def test_request_hash_changes_when_any_input_changes():
    base = {
        "event_id": "e",
        "original_event": {"time": 1},
        "updated_event": {"class_uid": 3002},
    }
    original_hash = RevalidationRepository.build_request_hash(**base)
    for key, value in [
        ("event_id", "other"),
        ("original_event", {"time": 2}),
        ("updated_event", {"class_uid": 3003}),
    ]:
        variant = {**base, key: value}
        assert RevalidationRepository.build_request_hash(**variant) != original_hash


def test_data_survives_new_repository_instance_on_same_file(tmp_path):
    db_path = str(tmp_path / "shared.db")
    first = RevalidationRepository(database_path=db_path)
    first.save(
        re_run_id="rerun-qa5", event_id="evt-5", idempotency_key="key-e",
        original_event=EVENT_A, updated_event=EVENT_B, valid=True, errors=[],
    )
    second = RevalidationRepository(database_path=db_path)
    row = second.get_by_id("rerun-qa5")
    assert row["updated_event"] == EVENT_B


def test_schema_migration_adds_request_hash_column(tmp_path):
    db_path = str(tmp_path / "legacy.db")
    connection = sqlite3.connect(db_path)
    # Simulate a database created by an earlier service version: no
    # request_hash column at all.
    connection.execute(
        """
        CREATE TABLE revalidation_runs (
            re_run_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            original_event TEXT NOT NULL,
            updated_event TEXT NOT NULL,
            valid INTEGER NOT NULL,
            errors TEXT NOT NULL
        )
        """
    )
    connection.commit()
    connection.close()

    # Initializing the repository must migrate: ADD COLUMN request_hash
    # (repository._create_tables), after which save/lookup works.
    repo = RevalidationRepository(database_path=db_path)
    repo.save(
        re_run_id="rerun-qa6", event_id="evt-6", idempotency_key="key-f",
        original_event={"time": 1}, updated_event={"time": 2}, valid=True, errors=[],
    )
    row = repo.get_by_idempotency_key("key-f")
    assert row["request_hash"]
    assert row["updated_event"] == {"time": 2}


def test_list_runs_ordered_by_insert(tmp_path):
    repo = _db(tmp_path)
    for i in range(3):
        repo.save(
            re_run_id=f"rerun-list-{i}", event_id=f"evt-{i}",
            idempotency_key=f"key-list-{i}",
            original_event={"time": i}, updated_event={"time": i + 1},
            valid=True, errors=[],
        )
    runs = repo.list_runs()
    assert [r["re_run_id"] for r in runs] == ["rerun-list-0", "rerun-list-1", "rerun-list-2"]
    assert runs[0]["updated_event"] == {"time": 1}

    limited = repo.list_runs(limit=2)
    assert len(limited) == 2