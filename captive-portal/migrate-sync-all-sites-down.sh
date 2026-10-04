#!/bin/bash
# Rollback: remove sync_to_all_sites from users and domain_policies.
set -e

psql "$DATABASE_URL" <<'SQL'
ALTER TABLE users          DROP COLUMN IF EXISTS sync_to_all_sites;
ALTER TABLE domain_policies DROP COLUMN IF EXISTS sync_to_all_sites;
SQL

echo "Rollback complete: sync_to_all_sites columns removed."
