#!/bin/bash
# Migration script to add admin table and create initial super admin

set -e

echo "================================================"
echo "Admin System Migration"
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

# Check if admins table already exists
TABLE_EXISTS=$(docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT to_regclass('public.admins') IS NOT NULL;")

if [ "$TABLE_EXISTS" = "t" ]; then
    echo "✓ Admin table already exists"
else
    echo "Creating admins table..."
    docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" <<'EOSQL'
        -- Admin users with role-based permissions
        CREATE TABLE IF NOT EXISTS admins (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            can_manage_users BOOLEAN DEFAULT TRUE NOT NULL,
            can_manage_vlans BOOLEAN DEFAULT FALSE NOT NULL,
            can_view_traffic BOOLEAN DEFAULT FALSE NOT NULL,
            can_manage_admins BOOLEAN DEFAULT FALSE NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            created_by INTEGER REFERENCES admins(id) ON DELETE SET NULL,
            last_login TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);
        
        COMMIT;
EOSQL
    echo "✓ Admin table created"
    
    # Verify table was created
    sleep 1
    TABLE_CHECK=$(docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT to_regclass('public.admins') IS NOT NULL;")
    if [ "$TABLE_CHECK" != "t" ]; then
        echo "ERROR: Failed to create admins table"
        exit 1
    fi
fi

echo ""
echo "================================================"
echo "Creating initial super admin account"
echo "================================================"
echo ""

# Get admin credentials from environment or use defaults
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
INITIAL_PASSWORD="${INITIAL_PASSWORD:-admin123}"

# Check if admin already exists
ADMIN_EXISTS=$(docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM admins WHERE username = '$ADMIN_USERNAME';")

if [ "$ADMIN_EXISTS" -gt 0 ]; then
    echo "⚠ Admin user '$ADMIN_USERNAME' already exists in database"
    echo "   Skipping creation..."
else
    echo "Creating admin user: $ADMIN_USERNAME"
    echo "Initial password: $INITIAL_PASSWORD"
    echo ""
    
    # Use Python to generate password hash
    PASSWORD_HASH=$(docker exec captive-portal-web python3 -c "
from werkzeug.security import generate_password_hash
print(generate_password_hash('$INITIAL_PASSWORD'))
")
    
    docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" <<-EOSQL
        INSERT INTO admins (username, password_hash, can_manage_users, can_manage_vlans, can_view_traffic, can_manage_admins)
        VALUES ('$ADMIN_USERNAME', '$PASSWORD_HASH', TRUE, TRUE, TRUE, TRUE);
EOSQL
    
    echo "✓ Super admin created successfully"
    echo ""
    echo "================================================"
    echo "IMPORTANT: Login credentials"
    echo "================================================"
    echo "Username: $ADMIN_USERNAME"
    echo "Password: $INITIAL_PASSWORD"
    echo ""
    echo "⚠ PLEASE CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN"
    echo "================================================"
fi

echo ""
echo "Migration completed successfully!"
echo ""
echo "Total admins in database:"
docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT username, can_manage_admins as is_super_admin, created_at FROM admins ORDER BY id;"
