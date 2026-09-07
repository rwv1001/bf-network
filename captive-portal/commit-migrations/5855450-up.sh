#!/bin/bash
set -e
psql "$DATABASE_URL" <<'SQL'
DELETE FROM vlan_mappings a USING vlan_mappings b
 WHERE a.id > b.id AND lower(a.status) = lower(b.status);
DELETE FROM vlan_mappings a USING vlan_mappings b
 WHERE a.id > b.id AND a.vlan_id = b.vlan_id;
CREATE UNIQUE INDEX IF NOT EXISTS ux_vlan_mappings_status_lower ON vlan_mappings (lower(status));
CREATE UNIQUE INDEX IF NOT EXISTS ux_vlan_mappings_vlan_id ON vlan_mappings(vlan_id);
SQL
echo "5855450 up migration complete."
