#!/bin/bash
set -e
psql "$DATABASE_URL" -c "ALTER TABLE vlan_mappings ADD COLUMN IF NOT EXISTS visible_vlans TEXT;"
