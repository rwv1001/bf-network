#!/bin/bash
# Migration script to add traffic_viewer_settings column to admins table

set -e

echo "================================================"
echo "Traffic Viewer Settings Migration"
echo "================================================"
echo ""

# Database connection details
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-captive_portal}"
DB_USER="${DB_USER:-portal_user}"

echo "Connecting to PostgreSQL database..."
echo "Host: $DB_HOST"
echo "Database: $DB_NAME"
echo ""

# Check if column already exists
COLUMN_EXISTS=$(docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='admins' AND column_name='traffic_viewer_settings');")

if [ "$COLUMN_EXISTS" = "t" ]; then
    echo "✓ traffic_viewer_settings column already exists in admins table"
else
    echo "Adding traffic_viewer_settings column to admins table..."
    docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" <<EOSQL
-- Add traffic_viewer_settings column to admins table
ALTER TABLE admins ADD COLUMN traffic_viewer_settings TEXT;
EOSQL
    echo "✓ traffic_viewer_settings column added successfully"
fi

echo ""
echo "================================================"
echo "Migration Complete!"
echo "================================================"
echo ""
echo "Traffic viewer column selections and filters will now persist per admin user."
echo "Settings are automatically saved when filtering/customizing the traffic viewer."
echo ""
