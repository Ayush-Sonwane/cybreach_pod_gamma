import hashlib
import json
import sqlite3
from typing import Any, Dict, Optional


class RevalidationRepository:

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
                CREATE TABLE IF NOT EXISTS revalidation_runs (
                    re_run_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_hash TEXT NOT NULL,
                    original_event TEXT NOT NULL,
                    updated_event TEXT NOT NULL,
                    valid INTEGER NOT NULL,
                    errors TEXT NOT NULL
                )
                """
            )

            # Add request_hash to an existing database created
            # by an earlier version of the service.
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(revalidation_runs)"
                ).fetchall()
            }

            if "request_hash" not in columns:
                connection.execute(
                    """
                    ALTER TABLE revalidation_runs
                    ADD COLUMN request_hash TEXT
                    """
                )

    @staticmethod
    def build_request_hash(
        event_id: str,
        original_event: Dict[str, Any],
        updated_event: Dict[str, Any],
    ) -> str:
        payload = {
            "event_id": event_id,
            "original_event": original_event,
            "event": updated_event,
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def get_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> Optional[Dict[str, Any]]:

        with self._connect() as connection:

            row = connection.execute(
                """
                SELECT
                    re_run_id,
                    event_id,
                    original_event,
                    updated_event,
                    valid,
                    errors,
                    request_hash
                FROM revalidation_runs
                WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()

        if row is None:
            return None

        return {
            "re_run_id": row[0],
            "event_id": row[1],
            "original_event": json.loads(row[2]),
            "updated_event": json.loads(row[3]),
            "valid": bool(row[4]),
            "errors": json.loads(row[5]),
            "request_hash": row[6],
        }

    def get_by_id(
        self,
        re_run_id: str,
    ) -> Optional[Dict[str, Any]]:

        with self._connect() as connection:

            row = connection.execute(
                """
                SELECT
                    re_run_id,
                    event_id,
                    original_event,
                    updated_event,
                    valid,
                    errors,
                    request_hash
                FROM revalidation_runs
                WHERE re_run_id = ?
                """,
                (re_run_id,),
            ).fetchone()

        if row is None:
            return None

        return {
            "re_run_id": row[0],
            "event_id": row[1],
            "original_event": json.loads(row[2]),
            "updated_event": json.loads(row[3]),
            "valid": bool(row[4]),
            "errors": json.loads(row[5]),
            "request_hash": row[6],
        }

    def save(
        self,
        re_run_id: str,
        event_id: str,
        idempotency_key: str,
        original_event: Dict[str, Any],
        updated_event: Dict[str, Any],
        valid: bool,
        errors: list,
    ):

        request_hash = self.build_request_hash(
            event_id=event_id,
            original_event=original_event,
            updated_event=updated_event,
        )

        with self._connect() as connection:

            connection.execute(
                """
                INSERT INTO revalidation_runs (
                    re_run_id,
                    event_id,
                    idempotency_key,
                    request_hash,
                    original_event,
                    updated_event,
                    valid,
                    errors
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    re_run_id,
                    event_id,
                    idempotency_key,
                    request_hash,
                    json.dumps(original_event),
                    json.dumps(updated_event),
                    int(valid),
                    json.dumps(errors),
                ),
            )