#!/bin/bash
# NAT Logging System - Complete Deployment Script
# Deploys UDM logger + Pi parser + database schema

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
UDM_HOST="192.168.1.1"
UDM_SSH_KEY="$HOME/.ssh/udm_key"
DB_NAME="${DB_NAME:-captive_portal}"
DB_USER="${DB_USER:-portal_user}"
DB_PASSWORD="${DB_PASSWORD:-change_this_password}"

echo "==================================================="
echo "NAT Logging System - Deployment"
echo "==================================================="
echo ""

# Step 1: Verify prerequisites
echo "Step 1: Verifying prerequisites..."
echo "---------------------------------------------------"

# Check SSH key
if [ ! -f "$UDM_SSH_KEY" ]; then
    echo "❌ ERROR: UDM SSH key not found: $UDM_SSH_KEY"
    echo "Please create SSH key first:"
    echo "  ssh-keygen -t ed25519 -f ~/.ssh/udm_key -N ''"
    echo "  ssh-copy-id -i ~/.ssh/udm_key root@$UDM_HOST"
    exit 1
fi
echo "✓ SSH key found: $UDM_SSH_KEY"

# Check UDM connectivity
echo -n "Testing UDM connectivity..."
if ssh -i "$UDM_SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no "root@$UDM_HOST" "echo ok" &>/dev/null; then
    echo " ✓"
else
    echo " ❌"
    echo "ERROR: Cannot connect to UDM at $UDM_HOST"
    echo "Please verify:"
    echo "  1. UDM is online"
    echo "  2. SSH is enabled on UDM"
    echo "  3. SSH key is authorized: ssh-copy-id -i ~/.ssh/udm_key root@$UDM_HOST"
    exit 1
fi

# Check database connectivity
echo -n "Testing database connectivity..."
if PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" &>/dev/null; then
    echo " ✓"
else
    echo " ❌"
    echo "ERROR: Cannot connect to PostgreSQL database"
    echo "Please verify captive portal database is running:"
    echo "  cd /home/admin/bf-network/captive-portal && docker compose ps"
    exit 1
fi

# Check Python dependencies
echo -n "Checking Python dependencies..."
if python3 -c "import psycopg2" 2>/dev/null; then
    echo " ✓"
else
    echo " ❌"
    echo "Installing psycopg2..."
    pip3 install psycopg2-binary
fi

echo ""

# Step 2: Deploy database schema
echo "Step 2: Deploying database schema..."
echo "---------------------------------------------------"
SCHEMA_FILE="$SCRIPT_DIR/../captive-portal/nat-sessions-schema.sql"
if [ -f "$SCHEMA_FILE" ]; then
    PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -f "$SCHEMA_FILE"
    echo "✓ Database schema deployed"
else
    echo "❌ ERROR: Schema file not found: $SCHEMA_FILE"
    exit 1
fi

echo ""

# Step 3: Deploy NAT logger to UDM
echo "Step 3: Deploying NAT logger to UDM..."
echo "---------------------------------------------------"
UDM_SCRIPT="$SCRIPT_DIR/udm-nat-logger-persist.sh"
if [ ! -f "$UDM_SCRIPT" ]; then
    echo "❌ ERROR: UDM install script not found: $UDM_SCRIPT"
    exit 1
fi

echo "Copying script to UDM..."
scp -i "$UDM_SSH_KEY" -o StrictHostKeyChecking=no "$UDM_SCRIPT" "root@$UDM_HOST:/tmp/udm-nat-logger-persist.sh"

echo "Executing installation on UDM..."
ssh -i "$UDM_SSH_KEY" -o StrictHostKeyChecking=no "root@$UDM_HOST" "bash /tmp/udm-nat-logger-persist.sh"

echo "✓ UDM NAT logger deployed and started"
echo ""

# Step 4: Update rsyslog.conf environment variable
echo "Step 4: Updating parser environment..."
echo "---------------------------------------------------"

# Create environment file for systemd service
ENV_FILE="/etc/systemd/system/nat-parser.service.d/override.conf"
sudo mkdir -p "$(dirname $ENV_FILE)"
sudo tee "$ENV_FILE" > /dev/null <<EOF
[Service]
Environment="DB_NAME=$DB_NAME"
Environment="DB_USER=$DB_USER"
Environment="DB_PASSWORD=$DB_PASSWORD"
EOF

echo "✓ Environment configured"
echo ""

# Step 5: Install and start parser service
echo "Step 5: Installing NAT parser service..."
echo "---------------------------------------------------"

# Make parser executable
chmod +x "$SCRIPT_DIR/nat-parser.py"

# Install systemd service
sudo cp "$SCRIPT_DIR/nat-parser.service" /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable nat-parser.service

# Restart service
sudo systemctl restart nat-parser.service

# Check status
if sudo systemctl is-active --quiet nat-parser.service; then
    echo "✓ NAT parser service installed and running"
else
    echo "❌ WARNING: Service installed but not running"
    echo "Check status: sudo systemctl status nat-parser.service"
fi

echo ""

# Step 6: Verify deployment
echo "Step 6: Verifying deployment..."
echo "---------------------------------------------------"

echo "UDM Logger Status:"
ssh -i "$UDM_SSH_KEY" "root@$UDM_HOST" "ps aux | grep nat_logger | grep -v grep || echo 'Not running'"

echo ""
echo "Parser Service Status:"
sudo systemctl status nat-parser.service --no-pager -l | head -20

echo ""
echo "Recent NAT logs:"
tail -5 /home/admin/bf-network/syslog-container/logs/remote-syslog.log 2>/dev/null || echo "No logs yet"

echo ""
echo "Database status:"
PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -c \
    "SELECT COUNT(*) as total_sessions FROM nat_sessions;"

echo ""
echo "==================================================="
echo "✓ Deployment Complete!"
echo "==================================================="
echo ""
echo "Monitoring commands:"
echo "  UDM logs:      ssh -i ~/.ssh/udm_key root@$UDM_HOST 'tail -f /var/log/messages | grep NAT-Logger'"
echo "  Pi syslog:     tail -f /home/admin/bf-network/syslog-container/logs/remote-syslog.log"
echo "  Parser logs:   sudo journalctl -u nat-parser.service -f"
echo "  Parser status: sudo systemctl status nat-parser.service"
echo ""
echo "Database queries:"
echo "  Active sessions:   SELECT * FROM nat_active_sessions;"
echo "  Stats by IP:       SELECT * FROM nat_session_stats_by_ip;"
echo "  Recent sessions:   SELECT * FROM nat_sessions ORDER BY session_end DESC LIMIT 10;"
echo ""
