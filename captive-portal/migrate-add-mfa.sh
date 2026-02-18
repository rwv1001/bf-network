#!/bin/bash

# Migration script to add MFA (Multi-Factor Authentication) columns to admins table

echo "Adding MFA columns to admins table..."

# Check if columns already exist
EXISTING=$(docker exec captive-portal-db psql -U portal_user -d captive_portal -tAc "
SELECT column_name FROM information_schema.columns 
WHERE table_name='admins' AND column_name IN ('mfa_enabled', 'mfa_secret');
")

if echo "$EXISTING" | grep -q "mfa_enabled"; then
    echo "✓ MFA columns already exist"
else
    echo "Adding mfa_enabled and mfa_secret columns..."
    docker exec captive-portal-db psql -U portal_user -d captive_portal <<SQL
    ALTER TABLE admins ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL;
    ALTER TABLE admins ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(32);
SQL
    echo "✓ MFA columns added successfully"
fi

echo ""
echo "Migration complete!"
echo ""
echo "Next steps:"
echo "1. Install MFA dependencies: docker exec captive-portal-web pip install pyotp==2.9.0 qrcode==7.4.2"
echo "2. Restart web container: docker restart captive-portal-web"
echo "3. Admins can enable MFA from their profile at /admin/mfa/setup"
