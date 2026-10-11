#!/bin/bash
# Rollback b633af: remove admin notes from switch_ports.
set -e

psql "$DATABASE_URL" <<'SQL'
ALTER TABLE switch_ports DROP COLUMN IF EXISTS notes;
SQL

echo "Rollback complete: switch_ports.notes removed."
