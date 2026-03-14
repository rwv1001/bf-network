#!/bin/bash
# Migration script to add email column to admins table

set -e

echo "================================================"
echo "Admin Email Migration"
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

# Check if email column already exists
COLUMN_EXISTS=$(docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='admins' AND column_name='email');")

if [ "$COLUMN_EXISTS" = "t" ]; then
    echo "✓ Email column already exists in admins table"
else
    echo "Adding email column to admins table..."
    docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" <<EOSQL
-- Add email column to admins table
ALTER TABLE admins ADD COLUMN email VARCHAR(255);

-- Create index on email for efficient lookups
CREATE INDEX idx_admins_email ON admins(email);
EOSQL
    echo "✓ Email column added successfully"
fi

echo ""
echo "================================================"
echo "Migration Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "1. Restart the web container: docker restart captive-portal-web"
echo "2. Log into super admin page: HTTPS_PORTAL_URL/admin"
echo "3. Go to Manage Admins and add email addresses to admin accounts"
echo "4. Admins with 'Manage Users and Devices' permission will receive email notifications"
echo ""
