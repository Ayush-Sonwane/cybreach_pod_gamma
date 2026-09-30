-- Migration: 002_webhook_connector.sql
-- Description: Local webhook health tracking only. The canonical connector
-- registry is owned by Pod Alpha and lives in the Alpha service's `connectors`
-- table. Gamma keeps only local webhook delivery health metrics here.

BEGIN;

-- 1. Persisted webhook delivery health counters (one row per connector)
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
    last_error TEXT
);

COMMIT;
