#!/bin/bash
set -e
psql "$DATABASE_URL" -c "DROP INDEX IF EXISTS ux_vlan_mappings_status_lower;"
psql "$DATABASE_URL" -c "DROP INDEX IF EXISTS ux_vlan_mappings_vlan_id;"
echo "5855450 down migration complete."
