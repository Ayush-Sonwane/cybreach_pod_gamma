-- Migration: 003_custom_ocsf_class.sql
-- Description: Adds registry for organization-specific custom OCSF schemas

BEGIN;

CREATE TABLE IF NOT EXISTS custom_ocsf_classes (
    id TEXT PRIMARY KEY,
    organization TEXT NOT NULL,
    class_name TEXT NOT NULL,
    class_uid INTEGER NOT NULL,
    category_uid INTEGER NOT NULL,
    version TEXT NOT NULL,
    schema TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (organization, class_uid)
);

COMMIT;