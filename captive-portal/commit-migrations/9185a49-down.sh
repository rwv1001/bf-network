#!/bin/bash
# commit-migrations/9185a49-down.sh
# Cleanup down-migration: restores firmware_test_table and firmware_test_col on users.
# Reverses 9185a49-up.sh (used when rolling back from the cleanup commit to 9185a49).
set -euo pipefail

echo "=== 9185a49 down-migration: restoring test table and column ==="

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS firmware_test_table (
    id         SERIAL PRIMARY KEY,
    test_key   VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS firmware_test_col VARCHAR(64);
SQL

echo "=== 9185a49 down-migration: complete ==="
