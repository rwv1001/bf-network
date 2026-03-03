#!/bin/bash
# commit-migrations/046af83-up.sh
# Test up-migration: creates firmware_test_table and adds firmware_test_col to users.
# Part of the firmware update test flow — safe to roll back with 046af83-down.sh.
set -euo pipefail

echo "=== 046af83 up-migration: adding test table and column ==="

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
-- Test table: created by the firmware update test migration
CREATE TABLE IF NOT EXISTS firmware_test_table (
    id         SERIAL PRIMARY KEY,
    test_key   VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Insert a marker row so we know the migration ran
INSERT INTO firmware_test_table (test_key)
VALUES ('046af83-up-migration-ran');

-- Test column on users
ALTER TABLE users ADD COLUMN IF NOT EXISTS firmware_test_col VARCHAR(64);
SQL

echo "=== 046af83 up-migration: complete ==="
