#!/bin/bash
# Migration b633af: admin notes on switch_ports. Notes are local to the portal
# and are not pushed to the switch.
set -e

psql "$DATABASE_URL" <<'SQL'
ALTER TABLE switch_ports
    ADD COLUMN IF NOT EXISTS notes VARCHAR(200) NOT NULL DEFAULT '';
SQL

echo "Migration complete: switch_ports.notes added."
