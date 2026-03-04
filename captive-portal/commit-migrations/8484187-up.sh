#!/bin/bash
set -e
psql "$DATABASE_URL" -c "CREATE TABLE IF NOT EXISTS firmware_test_table (id SERIAL PRIMARY KEY, label TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());"
psql "$DATABASE_URL" -c "INSERT INTO firmware_test_table (label) VALUES ('test-row') ON CONFLICT DO NOTHING;"
psql "$DATABASE_URL" -c "ALTER TABLE users ADD COLUMN IF NOT EXISTS firmware_test_col TEXT;"
