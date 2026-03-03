#!/bin/bash
# b0330fd-down.sh — restores firmware test DB objects (rollback)
set -euo pipefail

echo "[b0330fd-down] Recreating firmware_test_table..."
psql "$DATABASE_URL" -c "CREATE TABLE IF NOT EXISTS firmware_test_table (id SERIAL PRIMARY KEY, label TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());"

echo "[b0330fd-down] Re-adding firmware_test_col to users..."
psql "$DATABASE_URL" -c "ALTER TABLE users ADD COLUMN IF NOT EXISTS firmware_test_col TEXT;"

echo "[b0330fd-down] Done."
