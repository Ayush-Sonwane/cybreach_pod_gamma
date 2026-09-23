# src/webhook/repository.py
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ConnectorRepository:
    """
    Persists webhook connector configuration and delivery health counters.

    Uses the existing SQLite persistence pattern from the revalidation
    service (raw sqlite3, no ORM). No separate store is introduced: connector
    config and health metrics live in the same connectors database.
    """

    def __init__(self, database_path: str = "connectors.db"):
        self.database_path = database_path
        self._create_tables()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _create_tables(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS connectors (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    hmac_enabled INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_health (
                    connector_id TEXT PRIMARY KEY,
                    delivered INTEGER NOT NULL DEFAULT 0,
                    valid_count INTEGER NOT NULL DEFAULT 0,
                    invalid_count INTEGER NOT NULL DEFAULT 0,
                    auth_failures INTEGER NOT NULL DEFAULT 0,
                    dlq_count INTEGER NOT NULL DEFAULT 0,
                    total_latency_ms INTEGER NOT NULL DEFAULT 0,
                    last_seen TEXT,
                    last_status TEXT,
                    last_error TEXT,
                    FOREIGN KEY (connector_id) REFERENCES connectors (id)
                )
                """
            )

    # ---------------------------------------------------------------
    # Connector configuration
    # ---------------------------------------------------------------

    def create_connector(
        self,
        connector_id: str,
        name: str,
        secret: str,
        hmac_enabled: bool = False,
        is_active: bool = True,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO connectors (
                    id, name, secret, hmac_enabled, is_active, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    connector_id,
                    name,
                    secret,
                    int(hmac_enabled),
                    int(is_active),
                    _utc_now(),
                ),
            )

    def get_connector(self, connector_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, name, secret, hmac_enabled, is_active, created_at
                FROM connectors
                WHERE id = ?
                """,
                (connector_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "name": row[1],
            "secret": row[2],
            "hmac_enabled": bool(row[3]),
            "is_active": bool(row[4]),
            "created_at": row[5],
        }

    def list_connectors(self, include_secret: bool = False) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, name, secret, hmac_enabled, is_active, created_at FROM connectors"
            ).fetchall()
        connectors = []
        for row in rows:
            connector = {
                "id": row[0],
                "name": row[1],
                "hmac_enabled": bool(row[3]),
                "is_active": bool(row[4]),
                "created_at": row[5],
            }
            if include_secret:
                connector["secret"] = row[2]
            connectors.append(connector)
        return connectors

    def delete_connector(self, connector_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM webhook_health WHERE connector_id = ?", (connector_id,))
            connection.execute("DELETE FROM connectors WHERE id = ?", (connector_id,))

    # ---------------------------------------------------------------
    # Health monitoring
    # ---------------------------------------------------------------

    def record_delivery(
        self,
        connector_id: str,
        status: str,
        latency_ms: int = 0,
        error: Optional[str] = None,
        dlq: bool = False,
    ) -> None:
        """
        Updates the aggregate health counters for a connector delivery.

        ``status`` is one of ``valid``, ``invalid`` or ``auth_failed``.
        """
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO webhook_health (
                    connector_id, delivered, valid_count, invalid_count,
                    auth_failures, dlq_count, total_latency_ms,
                    last_seen, last_status, last_error
                )
                VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (connector_id) DO UPDATE SET
                    delivered = webhook_health.delivered + 1,
                    valid_count = webhook_health.valid_count + ?,
                    invalid_count = webhook_health.invalid_count + ?,
                    auth_failures = webhook_health.auth_failures + ?,
                    dlq_count = webhook_health.dlq_count + ?,
                    total_latency_ms = webhook_health.total_latency_ms + ?,
                    last_seen = ?,
                    last_status = ?,
                    last_error = ?
                """,
                (
                    connector_id,
                    int(status == "valid"),
                    int(status == "invalid"),
                    int(status == "auth_failed"),
                    int(dlq),
                    latency_ms,
                    _utc_now(),
                    status,
                    error,
                    int(status == "valid"),
                    int(status == "invalid"),
                    int(status == "auth_failed"),
                    int(dlq),
                    latency_ms,
                    _utc_now(),
                    status,
                    error,
                ),
            )

    def get_health(self) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    connector_id, delivered, valid_count, invalid_count,
                    auth_failures, dlq_count, total_latency_ms,
                    last_seen, last_status, last_error
                FROM webhook_health
                ORDER BY connector_id
                """
            ).fetchall()
        health = []
        for row in rows:
            delivered = row[1]
            health.append({
                "connector_id": row[0],
                "delivered": delivered,
                "valid_count": row[2],
                "invalid_count": row[3],
                "auth_failures": row[4],
                "dlq_count": row[5],
                "avg_latency_ms": int(row[6] / delivered) if delivered else 0,
                "last_seen": row[7],
                "last_status": row[8],
                "last_error": row[9],
            })
        return health

    def get_health_by_connector(self, connector_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    connector_id, delivered, valid_count, invalid_count,
                    auth_failures, dlq_count, total_latency_ms,
                    last_seen, last_status, last_error
                FROM webhook_health
                WHERE connector_id = ?
                """,
                (connector_id,),
            ).fetchone()
        if row is None:
            return None
        delivered = row[1]
        return {
            "connector_id": row[0],
            "delivered": delivered,
            "valid_count": row[2],
            "invalid_count": row[3],
            "auth_failures": row[4],
            "dlq_count": row[5],
            "avg_latency_ms": int(row[6] / delivered) if delivered else 0,
            "last_seen": row[7],
            "last_status": row[8],
            "last_error": row[9],
        }