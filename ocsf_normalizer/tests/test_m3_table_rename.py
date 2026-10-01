"""M3: Gamma's local webhook credential table must not collide with Alpha's.

M3 found Gamma creating a table literally named `connectors` - a different schema
under the same name as Alpha's canonical registry, which would collide in a
merged database. It is now `webhook_connector_credentials`, which says what it
holds: the per-connector shared secret and HMAC flag that
`/api/v2/webhook/ingest` authenticates against. The credential cannot simply be
dropped, because Alpha's registry does not model a webhook ingest secret.

The rename therefore has to migrate databases written before it, and that is the
part worth testing: a silent failure here would leave an existing deployment
either crashing on a missing table or, worse, quietly writing its ingest
credentials into a table Alpha also owns.
"""
import sqlite3

from src.webhook.repository import ConnectorRepository

LEGACY_HEALTH_DDL = (
    "CREATE TABLE webhook_health ("
    "connector_id TEXT PRIMARY KEY, "
    "delivered INTEGER NOT NULL DEFAULT 0, "
    "valid_count INTEGER NOT NULL DEFAULT 0, "
    "invalid_count INTEGER NOT NULL DEFAULT 0, "
    "auth_failures INTEGER NOT NULL DEFAULT 0, "
    "dlq_count INTEGER NOT NULL DEFAULT 0, "
    "total_latency_ms INTEGER NOT NULL DEFAULT 0, "
    "last_seen TEXT, "
    "last_status TEXT, "
    "last_error TEXT, "
    "FOREIGN KEY (connector_id) REFERENCES connectors (id))"
)


def _write_legacy_database(path: str) -> None:
    """Recreate exactly what the pre-rename code left on disk."""
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE connectors (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
        "secret TEXT NOT NULL, hmac_enabled INTEGER NOT NULL DEFAULT 0, "
        "is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)"
    )
    connection.execute(LEGACY_HEALTH_DDL)
    connection.execute(
        "INSERT INTO connectors (id, name, secret, hmac_enabled, is_active, created_at) "
        "VALUES ('legacy-1', 'Old SIEM', 'oldsecret', 1, 1, '2026-01-01T00:00:00Z')"
    )
    connection.execute(
        "INSERT INTO webhook_health (connector_id, delivered, valid_count) "
        "VALUES ('legacy-1', 7, 5)"
    )
    connection.commit()
    connection.close()


def _tables(path: str):
    connection = sqlite3.connect(path)
    try:
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        connection.close()


def test_legacy_connectors_table_is_renamed_not_duplicated(tmp_path):
    path = str(tmp_path / "legacy.db")
    _write_legacy_database(path)

    ConnectorRepository(database_path=path)

    tables = _tables(path)
    assert "connectors" not in tables, "the legacy table name must not survive"
    assert "webhook_connector_credentials" in tables


def test_rename_preserves_existing_connector_credentials(tmp_path):
    path = str(tmp_path / "legacy.db")
    _write_legacy_database(path)

    repo = ConnectorRepository(database_path=path)

    connector = repo.get_connector("legacy-1")
    assert connector is not None
    assert connector["secret"] == "oldsecret"
    assert connector["hmac_enabled"] is True
    assert connector["name"] == "Old SIEM"


def test_rename_preserves_health_counters_and_rewrites_the_foreign_key(tmp_path):
    path = str(tmp_path / "legacy.db")
    _write_legacy_database(path)

    repo = ConnectorRepository(database_path=path)

    health = repo.get_health_by_connector("legacy-1", "")
    assert health is not None
    assert health["delivered"] == 7
    assert health["valid_count"] == 5

    connection = sqlite3.connect(path)
    try:
        ddl = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='webhook_health'"
        ).fetchone()[0]
    finally:
        connection.close()
    # A foreign key still pointing at a table that no longer exists would be
    # silently unenforced, so this is what keeps referential integrity real.
    assert "webhook_connector_credentials" in ddl
    assert "REFERENCES connectors" not in ddl


def test_tenant_column_is_still_added_to_the_renamed_table(tmp_path):
    """The B11 tenant migration must keep working after the rename."""
    path = str(tmp_path / "legacy.db")
    _write_legacy_database(path)

    ConnectorRepository(database_path=path)

    connection = sqlite3.connect(path)
    try:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(webhook_connector_credentials)"
            )
        }
    finally:
        connection.close()
    assert "tenant_id" in columns


def test_fresh_database_never_creates_a_table_named_connectors(tmp_path):
    """The M3 guarantee, checked on a clean install rather than a migration."""
    path = str(tmp_path / "fresh.db")

    ConnectorRepository(database_path=path)

    assert "connectors" not in _tables(path)