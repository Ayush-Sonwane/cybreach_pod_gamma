-- Migration: 002_webhook_connector.sql
-- Description: Adds generic webhook connector config + health monitoring tables

BEGIN;

-- 1. Per-connector webhook configuration (shared secret / HMAC)
CREATE TABLE IF NOT EXISTS connectors (
    id TEXT PRIMARY KEY,               -- unique connector identifier (sent via X-Connector-Id)
    name TEXT NOT NULL,                -- human-readable connector name
    secret TEXT NOT NULL,              -- per-connector shared secret (HMAC key / secret header)
    hmac_enabled BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Persisted webhook delivery health counters (one row per connector)
CREATE TABLE IF NOT EXISTS webhook_health (
    connector_id TEXT PRIMARY KEY REFERENCES connectors(id) ON DELETE CASCADE,
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
