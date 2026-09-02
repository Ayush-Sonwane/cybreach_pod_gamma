"""SQLite persistence for automated re-validation schedules.

The scheduler engine (separate work stream) consumes rows from this
table; this module only owns configuration CRUD plus run bookkeeping
(claim/release), so it has no dependency on the scheduler itself.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class DuplicateScheduleError(Exception):
    """Raised when a schedule with the same id already exists."""


class ScheduleRepository:

    def __init__(self, database_path: str = "revalidation.db"):
        self.database_path = database_path
        self._create_tables()

    def _connect(self):
        connection = sqlite3.connect(self.database_path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _create_tables(self):
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS revalidation_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL,
                    missed_run_policy TEXT NOT NULL
                        CHECK (missed_run_policy IN ('skip', 'run_once')),
                    enabled INTEGER NOT NULL DEFAULT 1,
                    request_template TEXT,
                    is_running INTEGER NOT NULL DEFAULT 0,
                    last_run_at REAL,
                    next_run_at REAL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def new_schedule_id() -> str:
        return f"sched-{uuid4_hex()}"

    def create(
        self,
        name: str,
        event_id: str,
        interval_seconds: int,
        missed_run_policy: str = "run_once",
        enabled: bool = True,
        request_template: Optional[Dict[str, Any]] = None,
        schedule_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        now = utc_now_iso()
        row_id = schedule_id or self.new_schedule_id()

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO revalidation_schedules (
                        schedule_id,
                        name,
                        event_id,
                        interval_seconds,
                        missed_run_policy,
                        enabled,
                        request_template,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row_id,
                        name,
                        event_id,
                        int(interval_seconds),
                        missed_run_policy,
                        int(enabled),
                        json.dumps(request_template)
                        if request_template is not None
                        else None,
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise DuplicateScheduleError(
                f"Schedule '{row_id}' already exists"
            ) from error

        return self.get(row_id)

    def get(
        self,
        schedule_id: str,
    ) -> Optional[Dict[str, Any]]:

        with self._connect() as connection:
            row = self._select_by_id(connection, schedule_id)

        if row is None:
            return None

        return self._row_to_dict(row)

    def list(
        self,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:

        query = """
            SELECT
                schedule_id,
                name,
                event_id,
                interval_seconds,
                missed_run_policy,
                enabled,
                request_template,
                is_running,
                last_run_at,
                next_run_at,
                created_at,
                updated_at
            FROM revalidation_schedules
        """

        params: tuple = ()

        if enabled is not None:
            query += " WHERE enabled = ?"
            params = (int(enabled),)

        query += " ORDER BY created_at ASC"

        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()

        return [self._row_to_dict(row) for row in rows]

    def update(
        self,
        schedule_id: str,
        fields: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        allowed_columns = {
            "name",
            "interval_seconds",
            "missed_run_policy",
            "enabled",
            "request_template",
            "is_running",
            "last_run_at",
            "next_run_at",
        }

        assignments = []
        params: List[Any] = []

        for column, value in fields.items():
            if column not in allowed_columns:
                continue

            assignments.append(f"{column} = ?")

            if column == "request_template":
                params.append(
                    json.dumps(value)
                    if value is not None
                    else None
                )
            elif column in ("enabled", "is_running"):
                params.append(int(value))
            else:
                params.append(value)

        if not assignments:
            return self.get(schedule_id)

        assignments.append("updated_at = ?")
        params.append(utc_now_iso())
        params.append(schedule_id)

        with self._connect() as connection:
            cursor = connection.execute(
                f"""
                UPDATE revalidation_schedules
                SET {', '.join(assignments)}
                WHERE schedule_id = ?
                """,
                tuple(params),
            )

            if cursor.rowcount == 0:
                return None

            row = self._select_by_id(connection, schedule_id)

        return self._row_to_dict(row)

    def delete(self, schedule_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM revalidation_schedules
                WHERE schedule_id = ?
                """,
                (schedule_id,),
            )

        return cursor.rowcount > 0

    def claim_run(self, schedule_id: str) -> bool:
        """Mark a schedule as running.

        Returns True only when the schedule was idle, which gives the
        executor a lightweight overlap guard without needing a lock.
        """

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE revalidation_schedules
                SET is_running = 1,
                    updated_at = ?
                WHERE schedule_id = ?
                  AND is_running = 0
                """,
                (utc_now_iso(), schedule_id),
            )

        return cursor.rowcount > 0

    def release_run(
        self,
        schedule_id: str,
        last_run_at: float,
        next_run_at: Optional[float] = None,
    ):
        """Clear the running flag after a run and advance bookkeeping."""

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE revalidation_schedules
                SET is_running = 0,
                    last_run_at = ?,
                    next_run_at = COALESCE(?, next_run_at),
                    updated_at = ?
                WHERE schedule_id = ?
                """,
                (
                    float(last_run_at),
                    next_run_at,
                    utc_now_iso(),
                    schedule_id,
                ),
            )

    @staticmethod
    def _select_by_id(connection, schedule_id: str):
        return connection.execute(
            """
            SELECT
                schedule_id,
                name,
                event_id,
                interval_seconds,
                missed_run_policy,
                enabled,
                request_template,
                is_running,
                last_run_at,
                next_run_at,
                created_at,
                updated_at
            FROM revalidation_schedules
            WHERE schedule_id = ?
            """,
            (schedule_id,),
        ).fetchone()

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        template = None

        if row[6] is not None:
            template = json.loads(row[6])

        return {
            "schedule_id": row[0],
            "name": row[1],
            "event_id": row[2],
            "interval_seconds": row[3],
            "missed_run_policy": row[4],
            "enabled": bool(row[5]),
            "request_template": template,
            "is_running": bool(row[7]),
            "last_run_at": row[8],
            "next_run_at": row[9],
            "created_at": row[10],
            "updated_at": row[11],
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def uuid4_hex() -> str:
    return uuid.uuid4().hex
