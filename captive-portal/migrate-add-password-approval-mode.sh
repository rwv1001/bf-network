#!/bin/bash
# Migration: add network_password_approval_mode column to users table
set -e

cd "$(dirname "$0")"

echo "Running migration: add network_password_approval_mode to users..."

docker compose exec -T db psql -U ${DB_USER:-portal_user} -d ${DB_NAME:-captive_portal} <<'SQL'
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS network_password_approval_mode VARCHAR(20);

COMMENT ON COLUMN users.network_password_approval_mode IS
    'NULL or ''always'' = auto-approve on correct password; ''admin_required'' = correct password still needs admin approval';

SELECT column_name, data_type, character_maximum_length
  FROM information_schema.columns
 WHERE table_name = 'users'
   AND column_name = 'network_password_approval_mode';
SQL

echo "Migration complete."
