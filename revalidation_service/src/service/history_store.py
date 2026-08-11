# revalidation_service/src/service/history_store.py
"""SQLite persistence for re-validation run history (Pod Gamma, Task 3).

Maintains the complete history of runs, stores before-and-after verdicts
(both snapshots in full), confidence scores and the rules responsible for
improvements/regressions.
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
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_event ON runs(event_id);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at);

CREATE TABLE IF NOT EXISTS run_payloads (
    run_id  TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
"""


class RevalidationHistoryStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save_run(self, run: RevalidationRun) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO runs "
            "(run_id, event_id, vendor, verdict, confidence_before, confidence_after, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run.run_id, run.event_id, run.vendor, run.verdict,
             run.confidence_before, run.confidence_after, run.created_at),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO run_payloads (run_id, payload) VALUES (?, ?)",
            (run.run_id, run.model_dump_json()),
        )
        self._conn.commit()

    def get_run(self, run_id: str) -> Optional[RevalidationRun]:
        row = self._conn.execute(
            "SELECT payload FROM run_payloads WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        return RevalidationRun.model_validate_json(row["payload"])

    def list_runs(self, limit: int = 50, event_id: Optional[str] = None) -> List[RevalidationRun]:
        query = (
            "SELECT p.payload FROM run_payloads p "
            "JOIN runs r ON r.run_id = p.run_id "
        )
        params: List = []
        if event_id:
            query += "WHERE r.event_id = ? "
            params.append(event_id)
        query += "ORDER BY r.created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [RevalidationRun.model_validate_json(r["payload"]) for r in rows]

    def latest_after(self, event_id: str) -> Optional[EventSnapshot]:
        """Most recent stored 'after' snapshot for an event (the next 'before')."""
        row = self._conn.execute(
            "SELECT payload FROM run_payloads WHERE run_id IN "
            "(SELECT run_id FROM runs WHERE event_id = ? ORDER BY created_at DESC LIMIT 1)",
            (event_id,),
        ).fetchone()
        if row is None:
            return None
        return RevalidationRun.model_validate_json(row["payload"]).after

    def all_runs(self) -> List[RevalidationRun]:
        rows = self._conn.execute("SELECT payload FROM run_payloads").fetchall()
        return [RevalidationRun.model_validate_json(r["payload"]) for r in rows]