#!/bin/bash
# Migration: add network_password_set_token and expires to users table
set -e
cd "$(dirname "$0")"

echo "Running migration: add network_password_set_token columns to users..."

docker compose exec -T db psql -U portal_user -d captive_portal <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'network_password_set_token'
    ) THEN
        ALTER TABLE users
            ADD COLUMN network_password_set_token VARCHAR(255),
            ADD COLUMN network_password_set_token_expires TIMESTAMP;
        CREATE INDEX IF NOT EXISTS ix_users_network_password_set_token
            ON users (network_password_set_token);
        RAISE NOTICE 'Added network_password_set_token columns to users.';
    ELSE
        RAISE NOTICE 'Columns already exist, skipping.';
    END IF;
END$$;
SQL

echo "Migration complete."
