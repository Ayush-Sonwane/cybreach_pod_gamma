"""Tests for SQLite run-history persistence.

B11: every store method is tenant-scoped, so these tests pass a tenant
explicitly and a dedicated case pins that one tenant cannot read another's runs.
"""
from src.service.delta_engine import evaluate
from src.service.history_store import RevalidationHistoryStore
from tests.samples import EVENT_ID, fixed_snapshot, flawed_snapshot

TENANT_A = "tenant-a"
TENANT_B = "tenant-b"


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
    store.save_run(run, TENANT_A)
    loaded = store.get_run("run-1", TENANT_A)
    assert loaded is not None
    assert loaded.run_id == "run-1"
    assert loaded.verdict == "IMPROVED"
    assert loaded.confidence_before == 79.0
    assert loaded.confidence_after == 100.0
    assert len(loaded.deltas) > 0
    assert loaded.after.event_id == EVENT_ID


def test_get_missing_run_returns_none(tmp_path):
    store = _make_store(tmp_path)
    assert store.get_run("nope", TENANT_A) is None


def test_list_runs_ordering_and_filter(tmp_path):
    store = _make_store(tmp_path)
    for run in _two_runs():
        store.save_run(run, TENANT_A)
    runs = store.list_runs(tenant_id=TENANT_A)
    assert [r.run_id for r in runs] == ["run-2", "run-1"]
    filtered = store.list_runs(event_id=EVENT_ID, tenant_id=TENANT_A)
    assert len(filtered) == 2
    assert store.list_runs(event_id="other", tenant_id=TENANT_A) == []


def test_latest_after_returns_last_snapshot(tmp_path):
    store = _make_store(tmp_path)
    run1, run2 = _two_runs()
    store.save_run(run1, TENANT_A)
    assert store.latest_after(EVENT_ID, TENANT_A).confidence.score == 100.0
    store.save_run(run2, TENANT_A)
    latest = store.latest_after(EVENT_ID, TENANT_A)
    assert latest.normalized == run2.after.normalized
    assert store.latest_after("unknown", TENANT_A) is None


def test_all_runs_returns_everything(tmp_path):
    store = _make_store(tmp_path)
    for run in _two_runs():
        store.save_run(run, TENANT_A)
    assert len(store.all_runs(TENANT_A)) == 2


# --- B11: tenant isolation -------------------------------------------------
#
# The store is the only thing standing between "authenticated" and "allowed to
# read this run", so the isolation itself needs a gate.

def test_a_run_is_invisible_to_another_tenant(tmp_path):
    store = _make_store(tmp_path)
    store.save_run(_two_runs()[0], TENANT_A)
    assert store.get_run("run-1", TENANT_B) is None


def test_list_runs_excludes_other_tenants(tmp_path):
    store = _make_store(tmp_path)
    store.save_run(_two_runs()[0], TENANT_A)
    store.save_run(_two_runs()[1], TENANT_B)
    assert [r.run_id for r in store.list_runs(tenant_id=TENANT_A)] == ["run-1"]
    assert [r.run_id for r in store.list_runs(tenant_id=TENANT_B)] == ["run-2"]


def test_all_runs_excludes_other_tenants(tmp_path):
    store = _make_store(tmp_path)
    store.save_run(_two_runs()[0], TENANT_A)
    store.save_run(_two_runs()[1], TENANT_B)
    assert len(store.all_runs(TENANT_A)) == 1
    assert len(store.all_runs(TENANT_B)) == 1


def test_latest_after_does_not_cross_tenants(tmp_path):
    """Two tenants ingesting the same event_id must not diff against each other."""
    store = _make_store(tmp_path)
    run1, run2 = _two_runs()
    store.save_run(run1, TENANT_A)
    store.save_run(run2, TENANT_B)
    # Tenant B's history is run-2, not tenant A's run-1.
    assert store.latest_after(EVENT_ID, TENANT_B).normalized == run2.after.normalized


def test_a_run_stored_before_tenant_scoping_stays_invisible(tmp_path):
    """A pre-B11 database is migrated, not rewritten.

    Its rows cannot be attributed to a tenant, so they must not surface under
    whichever tenant happens to query first.
    """
    import sqlite3

    db_path = str(tmp_path / "legacy.db")
    legacy = sqlite3.connect(db_path)
    legacy.executescript(
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, vendor TEXT NOT NULL,
            verdict TEXT NOT NULL, confidence_before REAL NOT NULL,
            confidence_after REAL NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE run_payloads (run_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        """
    )
    run = _two_runs()[0]
    legacy.execute(
        "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)",
        (run.run_id, run.event_id, run.vendor, run.verdict,
         run.confidence_before, run.confidence_after, run.created_at),
    )
    legacy.execute(
        "INSERT INTO run_payloads VALUES (?, ?)", (run.run_id, run.model_dump_json())
    )
    legacy.commit()
    legacy.close()

    store = RevalidationHistoryStore(db_path)
    assert store.all_runs(TENANT_A) == []
    assert store.get_run("run-1", TENANT_A) is None
    # ...and the migrated schema still accepts new, attributed writes.
    store.save_run(run, TENANT_A)
    assert len(store.all_runs(TENANT_A)) == 1
