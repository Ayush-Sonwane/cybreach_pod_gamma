import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CustomOCSFClassRepository:
    """
    Persists organization-specific custom OCSF class schemas
    in the shared SQLite database.
    """

    def __init__(self, database_path: str = "connectors.db"):
        self.database_path = database_path
        self._create_table()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _create_table(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS custom_ocsf_classes (
                    id TEXT PRIMARY KEY,
                    organization TEXT NOT NULL,
                    class_name TEXT NOT NULL,
                    class_uid INTEGER NOT NULL,
                    category_uid INTEGER NOT NULL,
                    version TEXT NOT NULL,
                    schema TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (organization, class_uid)
                )
                """
            )

    def create_class(
        self,
        class_id: str,
        organization: str,
        class_name: str,
        class_uid: int,
        category_uid: int,
        version: str,
        schema: Dict[str, Any],
    ) -> Dict[str, Any]:

        now = _utc_now()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO custom_ocsf_classes (
                    id,
                    organization,
                    class_name,
                    class_uid,
                    category_uid,
                    version,
                    schema,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    class_id,
                    organization,
                    class_name,
                    class_uid,
                    category_uid,
                    version,
                    json.dumps(schema),
                    now,
                    now,
                ),
            )

        return self.get_class(class_id)

    def get_class(self, class_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    organization,
                    class_name,
                    class_uid,
                    category_uid,
                    version,
                    schema,
                    created_at,
                    updated_at
                FROM custom_ocsf_classes
                WHERE id = ?
                """,
                (class_id,),
            ).fetchone()

        if row is None:
            return None

        return {
            "id": row[0],
            "organization": row[1],
            "class_name": row[2],
            "class_uid": row[3],
            "category_uid": row[4],
            "version": row[5],
            "schema": json.loads(row[6]),
            "created_at": row[7],
            "updated_at": row[8],
        }

    def list_classes(
        self,
        organization: Optional[str] = None,
    ) -> List[Dict[str, Any]]:

        with self._connect() as connection:
            if organization:
                rows = connection.execute(
                    """
                    SELECT
                        id,
                        organization,
                        class_name,
                        class_uid,
                        category_uid,
                        version,
                        schema,
                        created_at,
                        updated_at
                    FROM custom_ocsf_classes
                    WHERE organization = ?
                    ORDER BY created_at DESC
                    """,
                    (organization,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT
                        id,
                        organization,
                        class_name,
                        class_uid,
                        category_uid,
                        version,
                        schema,
                        created_at,
                        updated_at
                    FROM custom_ocsf_classes
                    ORDER BY created_at DESC
                    """
                ).fetchall()

        return [
            {
                "id": row[0],
                "organization": row[1],
                "class_name": row[2],
                "class_uid": row[3],
                "category_uid": row[4],
                "version": row[5],
                "schema": json.loads(row[6]),
                "created_at": row[7],
                "updated_at": row[8],
            }
            for row in rows
        ]