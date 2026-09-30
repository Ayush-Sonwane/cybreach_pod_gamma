# revalidation_service/src/service/history_store.py
"""SQLite persistence for re-validation run history (Pod Gamma, Task 3).

Maintains the complete history of runs, stores before-and-after verdicts
(both snapshots in full), confidence scores and the rules responsible for
improvements/regressions.

B11: every row is tenant-scoped. The store previously had no notion of a tenant,
so `GET /api/v2/revalidate/runs` returned every tenant's runs and
`GET /api/v2/revalidate/metrics` averaged across all of them -- a cross-tenant
read that a module JWT alone does not prevent. Every public method therefore
takes `tenant_id` and filters on it; the column lives on `runs` and is joined
into the payload lookups so `run_payloads` needs no duplicate copy.
"""
import json
import sqlite3
from typing import List, Optional

from src.core.contracts import EventSnapshot, RevalidationRun

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id           TEXT PRIMARY KEY,
    event_id         TEXT NOT NULL,
    vendor           TEXT NOT NULL,
    verdict          TEXT NOT NULL,
    confidence_before REAL NOT NULL,
    confidence_after  REAL NOT NULL,
    created_at       TEXT NOT NULL,
    tenant_id        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_runs_event ON runs(event_id);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at);

CREATE TABLE IF NOT EXISTS run_payloads (
    run_id  TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
"""


def _add_tenant_column(conn: sqlite3.Connection) -> None:
    """Bring a pre-B11 database up to the tenant-scoped schema.

    `CREATE TABLE IF NOT EXISTS` is a no-op against an existing `runs` table, so
    a database created before this change would otherwise keep serving unscoped
    rows (and every insert below would fail on the missing column). The index is
    created here rather than in `SCHEMA` for the same reason: `SCHEMA` runs
    before the column exists, so an index over it would fail to create.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
    if "tenant_id" not in columns:
        # Existing rows predate tenant scoping and cannot be attributed to a
        # tenant, so they stay invisible rather than being claimed by whichever
        # tenant queries first. The default '' keeps old inserts working.
        conn.execute("ALTER TABLE runs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_tenant ON runs(tenant_id)")


class RevalidationHistoryStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        _add_tenant_column(self._conn)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save_run(self, run: RevalidationRun, tenant_id: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO runs "
            "(run_id, event_id, vendor, verdict, confidence_before, confidence_after, created_at, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run.run_id, run.event_id, run.vendor, run.verdict,
             run.confidence_before, run.confidence_after, run.created_at, tenant_id),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO run_payloads (run_id, payload) VALUES (?, ?)",
            (run.run_id, run.model_dump_json()),
        )
        self._conn.commit()

    def get_run(self, run_id: str, tenant_id: str) -> Optional[RevalidationRun]:
        row = self._conn.execute(
            "SELECT p.payload FROM run_payloads p "
            "JOIN runs r ON r.run_id = p.run_id "
            "WHERE p.run_id = ? AND r.tenant_id = ?",
            (run_id, tenant_id),
        ).fetchone()
        if row is None:
            return None
        return RevalidationRun.model_validate_json(row["payload"])

    def list_runs(
        self,
        limit: int = 50,
        event_id: Optional[str] = None,
        tenant_id: str = "",
    ) -> List[RevalidationRun]:
        query = (
            "SELECT p.payload FROM run_payloads p "
            "JOIN runs r ON r.run_id = p.run_id "
            "WHERE r.tenant_id = ? "
        )
        params: List = [tenant_id]
        if event_id:
            query += "AND r.event_id = ? "
            params.append(event_id)
        query += "ORDER BY r.created_at DESC, r.run_id DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [RevalidationRun.model_validate_json(r["payload"]) for r in rows]

    def latest_after(
        self, event_id: str, tenant_id: str = ""
    ) -> Optional[EventSnapshot]:
        """Most recent stored 'after' snapshot for an event (the next 'before').

        Scoped by tenant: two tenants ingesting the same `event_id` must not
        compute their improvement delta against each other's history.

        `run_id DESC` breaks ties on `created_at`, which is only microsecond
        resolution and therefore unordered in SQL when two runs land in the same
        microsecond -- without it "the most recent run" was whichever row the
        query planner happened to return first.
        """
        row = self._conn.execute(
            "SELECT payload FROM run_payloads WHERE run_id IN "
            "(SELECT run_id FROM runs WHERE event_id = ? AND tenant_id = ? "
            "ORDER BY created_at DESC, run_id DESC LIMIT 1)",
            (event_id, tenant_id),
        ).fetchone()
        if row is None:
            return None
        return RevalidationRun.model_validate_json(row["payload"]).after

    def all_runs(self, tenant_id: str = "") -> List[RevalidationRun]:
        rows = self._conn.execute(
            "SELECT p.payload FROM run_payloads p "
            "JOIN runs r ON r.run_id = p.run_id "
            "WHERE r.tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        return [RevalidationRun.model_validate_json(r["payload"]) for r in rows]
