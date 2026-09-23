-- Migration: 002_revalidation_schedules.sql
-- Description: Adds configuration tables for automated re-validation schedules

BEGIN;

-- 1. Schedule configuration consumed by the re-validation scheduler engine.
--    Interval bounds are enforced in application code (interval.py) so they can be tuned via env vars without a migration.
CREATE TABLE IF NOT EXISTS revalidation_schedules (
    schedule_id TEXT PRIMARY KEY,                      -- server-generated id ("sched-<hex>")
    name TEXT NOT NULL,                                -- human-readable schedule name
    event_id TEXT NOT NULL,                            -- OCSF event this schedule re-validates
    interval_seconds INTEGER NOT NULL,                 -- cadence between automated runs
    missed_run_policy VARCHAR(20) NOT NULL DEFAULT 'run_once'
        CHECK (missed_run_policy IN ('skip', 'run_once')),
    enabled BOOLEAN DEFAULT TRUE,
    request_template JSONB,                            -- optional static payload; resolved from stored runs when NULL
    is_running BOOLEAN DEFAULT FALSE,                  -- overlap guard: set while an automated run executes
    last_run_at DOUBLE PRECISION,                      -- epoch seconds of the last completed run
    next_run_at DOUBLE PRECISION,                      -- epoch seconds of the next scheduled run
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_revalidation_schedules_enabled
    ON revalidation_schedules (enabled);

CREATE INDEX IF NOT EXISTS idx_revalidation_schedules_event_id
    ON revalidation_schedules (event_id);

COMMIT;
