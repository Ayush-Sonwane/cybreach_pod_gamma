"""Tests for SQLite run-history persistence."""
from src.service.delta_engine import evaluate
from src.service.history_store import RevalidationHistoryStore
from tests.samples import EVENT_ID, fixed_snapshot, flawed_snapshot


def _make_store(tmp_path):
    return RevalidationHistoryStore(str(tmp_path / "history.db"))


def _two_runs():
    return [
        evaluate(flawed_snapshot(), fixed_snapshot(), run_id="run-1"),
        evaluate(fixed_snapshot(), fixed_snapshot(), run_id="run-2"),
    ]


def test_save_and_get_roundtrip(tmp_path):
    store = _make_store(tmp_path)
    run = _two_runs()[0]
    store.save_run(run)
    loaded = store.get_run("run-1")
    assert loaded is not None
    assert loaded.run_id == "run-1"
    assert loaded.verdict == "IMPROVED"
    assert loaded.confidence_before == 79.0
    assert loaded.confidence_after == 100.0
    assert len(loaded.deltas) > 0
    assert loaded.after.event_id == EVENT_ID


def test_get_missing_run_returns_none(tmp_path):
    store = _make_store(tmp_path)
    assert store.get_run("nope") is None


def test_list_runs_ordering_and_filter(tmp_path):
    store = _make_store(tmp_path)
    for run in _two_runs():
        store.save_run(run)
    runs = store.list_runs()
    assert [r.run_id for r in runs] == ["run-2", "run-1"]
    filtered = store.list_runs(event_id=EVENT_ID)
    assert len(filtered) == 2
    assert store.list_runs(event_id="other") == []


def test_latest_after_returns_last_snapshot(tmp_path):
    store = _make_store(tmp_path)
    run1, run2 = _two_runs()
    store.save_run(run1)
    assert store.latest_after(EVENT_ID).confidence.score == 100.0
    store.save_run(run2)
    latest = store.latest_after(EVENT_ID)
    assert latest.normalized == run2.after.normalized
    assert store.latest_after("unknown") is None


def test_all_runs_returns_everything(tmp_path):
    store = _make_store(tmp_path)
    for run in _two_runs():
        store.save_run(run)
    assert len(store.all_runs()) == 2