#!/bin/bash
set -e
psql "$DATABASE_URL" -c "ALTER TABLE vlan_mappings DROP COLUMN IF EXISTS allow_doh;"
psql "$DATABASE_URL" -c "ALTER TABLE vlan_mappings DROP COLUMN IF EXISTS visible_vlans;"
echo "245da90 down migration complete."
