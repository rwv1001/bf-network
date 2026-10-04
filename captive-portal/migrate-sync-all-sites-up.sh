#!/bin/bash
# Migration: Add sync_to_all_sites to users and domain_policies (cross-site
# full replication of selected users/domains via bf-central).
set -e

psql "$DATABASE_URL" <<'SQL'
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS sync_to_all_sites BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE domain_policies
    ADD COLUMN IF NOT EXISTS sync_to_all_sites BOOLEAN NOT NULL DEFAULT FALSE;
SQL

echo "Migration complete: sync_to_all_sites columns added."
