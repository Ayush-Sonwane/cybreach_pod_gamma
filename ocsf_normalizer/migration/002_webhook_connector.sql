-- Migration: 002_webhook_connector.sql
-- Description: Gamma's LOCAL webhook tables. The canonical connector registry is
-- owned by Pod Alpha and lives in the Alpha service's `connectors` table
-- (see contracts/CONNECTOR_FRAMEWORK.md). Nothing here is a second registry.
--
-- M3: this migration used to create a table literally named `connectors`, which
-- was a duplicate of Alpha's registry by name (different columns, same table
-- name) and would collide in a merged database. It no longer does. The local
-- credential store is named `webhook_connector_credentials` to say what it
-- actually holds: the per-connector shared secret and HMAC flag that
-- `/api/v2/webhook/ingest` authenticates against. That credential cannot simply
-- be dropped, because Alpha's registry does not model a webhook ingest secret,
-- but it is not connector *configuration* and must not be read as such.
--
-- Renaming is done by `src/webhook/repository.py` on open, which issues
-- `ALTER TABLE connectors RENAME TO webhook_connector_credentials` when it
-- finds the legacy name; SQLite rewrites `webhook_health`'s foreign key with it,
-- so an existing database keeps its connectors and stays referentially valid.

BEGIN;

-- 1. Per-connector webhook ingest credentials (local, not the registry).
-- `tenant_id` scopes the operator routes; the ingest path resolves by id alone
-- because its credential is the connector's own secret, not a module JWT.
CREATE TABLE IF NOT EXISTS webhook_connector_credentials (
    id TEXT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    secret TEXT NOT NULL,
    hmac_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    tenant_id TEXT NOT NULL DEFAULT ''
);

-- 2. Persisted webhook delivery health counters (one row per connector)
-- This table is local observability state only; it is not the canonical
-- connector registry. The authoritative registry is Alpha's `connectors` table.
CREATE TABLE IF NOT EXISTS webhook_health (
    connector_id TEXT PRIMARY KEY,
    delivered INTEGER NOT NULL DEFAULT 0,
    valid_count INTEGER NOT NULL DEFAULT 0,
    invalid_count INTEGER NOT NULL DEFAULT 0,
    auth_failures INTEGER NOT NULL DEFAULT 0,
    dlq_count INTEGER NOT NULL DEFAULT 0,
    total_latency_ms BIGINT NOT NULL DEFAULT 0,
    last_seen TIMESTAMP WITH TIME ZONE,
    last_status VARCHAR(20),
    last_error TEXT,
    FOREIGN KEY (connector_id) REFERENCES webhook_connector_credentials (id)
);

CREATE INDEX IF NOT EXISTS idx_webhook_connector_credentials_tenant
    ON webhook_connector_credentials (tenant_id);

COMMIT;