#!/bin/bash
# 6434a23-up.sh
# Applies test DB migration: creates firmware_test_table and adds firmware_test_col to users.
set -euo pipefail

echo "[6434a23-up] Creating firmware_test_table..."
psql "$DATABASE_URL" <<'SQL'
CREATE TABLE IF NOT EXISTS firmware_test_table (
    id         SERIAL PRIMARY KEY,
    label      TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO firmware_test_table (label) VALUES ('test-row-from-6434a23-up');
SQL

echo "[6434a23-up] Adding firmware_test_col to users..."
psql "$DATABASE_URL" <<'SQL'
ALTER TABLE users ADD COLUMN IF NOT EXISTS firmware_test_col TEXT;
SQL

echo "[6434a23-up] Done."
