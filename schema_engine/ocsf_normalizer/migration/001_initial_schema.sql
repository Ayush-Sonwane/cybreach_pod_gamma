-- Migration: 001_initial_schema.sql
-- Description: Creates initial tables for OCSF log normalization pipeline

BEGIN;

-- 1. Table for storing raw incoming SIEM logs before processing
CREATE TABLE IF NOT EXISTS raw_logs (
    id SERIAL PRIMARY KEY,
    vendor_source VARCHAR(50) NOT NULL,               -- e.g., 'splunk', 'qradar', 'ecs'
    raw_payload JSONB NOT NULL,                       -- Raw JSON payload received
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for searching raw logs by vendor or timestamp
CREATE INDEX IF NOT EXISTS idx_raw_logs_vendor ON raw_logs(vendor_source);
CREATE INDEX IF NOT EXISTS idx_raw_logs_received ON raw_logs(received_at);


-- 2. Table for storing normalized OCSF events
CREATE TABLE IF NOT EXISTS normalized_events (
    id SERIAL PRIMARY KEY,
    raw_log_id INT REFERENCES raw_logs(id) ON DELETE SET NULL,
    class_uid INT NOT NULL,                           -- e.g., 3002 (Authentication)
    category_uid INT NOT NULL,                        -- e.g., 3 (Identity & Access)
    activity_id INT,
    severity_id INT,
    event_time TIMESTAMP WITH TIME ZONE,              -- Converted OCSF timestamp
    ocsf_payload JSONB NOT NULL,                      -- Full normalized OCSF event JSON
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for querying normalized events efficiently
CREATE INDEX IF NOT EXISTS idx_ocsf_class ON normalized_events(class_uid);
CREATE INDEX IF NOT EXISTS idx_ocsf_time ON normalized_events(event_time);


-- 3. Table for tracking normalization execution logs & errors
CREATE TABLE IF NOT EXISTS normalization_logs (
    id SERIAL PRIMARY KEY,
    raw_log_id INT REFERENCES raw_logs(id) ON DELETE CASCADE,
    vendor VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,                      -- 'SUCCESS', 'FAILED', 'VALIDATION_ERROR'
    error_message TEXT,
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-- 4. Table for vendor configuration metadata
CREATE TABLE IF NOT EXISTS vendor_configs (
    id SERIAL PRIMARY KEY,
    vendor_name VARCHAR(50) UNIQUE NOT NULL,          -- 'splunk', 'qradar', 'ecs', 'asim', 'logscale'
    adapter_class VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Populate initial supported vendor records
INSERT INTO vendor_configs (vendor_name, adapter_class) VALUES
    ('splunk', 'SplunkAdapter'),
    ('qradar', 'QRadarAdapter'),
    ('ecs', 'ECSAdapter'),
    ('asim', 'ASIMAdapter'),
    ('logscale', 'LogScaleAdapter')
ON CONFLICT (vendor_name) DO NOTHING;

COMMIT;