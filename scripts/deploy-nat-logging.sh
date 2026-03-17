#!/bin/bash
# NAT Logging System - Complete Deployment Script
# Deploys UDM logger + Pi parser + database schema

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
UDM_HOST="${UDM_HOST:-192.168.1.1}"
UDM_SSH_KEY="$HOME/.ssh/udm_key"

# Source credentials from captive-portal .env if not already set in environment
ENV_FILE="$SCRIPT_DIR/../captive-portal/.env"
if [ -f "$ENV_FILE" ]; then
    # Only export lines that are valid KEY=VALUE pairs (skip comments and prose)
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        [ -z "${!key+x}" ] && export "$key"="$value"
    done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$ENV_FILE")
fi

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
if docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" &>/dev/null; then
    echo " ✓"
else
    echo " ❌"
    echo "ERROR: Cannot connect to PostgreSQL database"
    echo "Please verify captive portal database is running:"
    echo "  cd /home/admin/bf-network/captive-portal && docker compose ps"
    exit 1
fi

echo ""

# Step 2: Deploy database schema
echo "Step 2: Deploying database schema..."
echo "---------------------------------------------------"
SCHEMA_FILE="$SCRIPT_DIR/../captive-portal/nat-sessions-schema.sql"
if [ -f "$SCHEMA_FILE" ]; then
    docker exec -i captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" < "$SCHEMA_FILE"
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
ssh -i "$UDM_SSH_KEY" -o StrictHostKeyChecking=no "root@$UDM_HOST" \
    "PORTAL_IP='${PORTAL_IP:?PORTAL_IP required}' USER_VLAN_MIN='${USER_VLAN_MIN:-192.168.2.0}' USER_VLAN_MAX='${USER_VLAN_MAX:-192.168.95.255}' bash /tmp/udm-nat-logger-persist.sh"

echo "✓ UDM NAT logger deployed and started"
echo ""

# Step 4: Stop legacy host nat-parser service if running (superseded by Docker container)
echo "Step 4: Checking for legacy host nat-parser service..."
echo "---------------------------------------------------"
if systemctl is-active --quiet nat-parser.service 2>/dev/null; then
    echo "Stopping legacy host nat-parser.service (superseded by Docker container)..."
    sudo systemctl stop nat-parser.service
    sudo systemctl disable nat-parser.service 2>/dev/null || true
    echo "✓ Legacy service stopped and disabled"
elif systemctl is-enabled --quiet nat-parser.service 2>/dev/null; then
    echo "Disabling legacy host nat-parser.service..."
    sudo systemctl disable nat-parser.service 2>/dev/null || true
    echo "✓ Legacy service disabled"
else
    echo "✓ No legacy host nat-parser service found"
fi

echo ""

# Step 5: Ensure Docker nat-parser container is running
echo "Step 5: Ensuring Docker nat-parser is running..."
echo "---------------------------------------------------"
cd "$SCRIPT_DIR/../captive-portal"
if docker compose ps nat-parser 2>/dev/null | grep -q 'Up'; then
    echo "✓ Docker nat-parser container already running"
else
    echo "Starting Docker nat-parser container..."
    docker compose up -d nat-parser
    echo "✓ Docker nat-parser container started"
fi
cd "$SCRIPT_DIR"

echo ""

# Step 6: Verify deployment
echo "Step 6: Verifying deployment..."
echo "---------------------------------------------------"

echo "UDM Logger Status:"
ssh -i "$UDM_SSH_KEY" "root@$UDM_HOST" "ps aux | grep nat_logger | grep -v grep || echo 'Not running'"

echo ""
echo "Parser Container Status:"
docker compose -f "$SCRIPT_DIR/../captive-portal/docker-compose.yml" ps nat-parser

echo ""
echo "Recent NAT logs:"
tail -5 /home/admin/bf-network/syslog-container/logs/remote-syslog.log 2>/dev/null || echo "No logs yet"

echo ""
echo "Database status:"
docker exec captive-portal-db psql -U "$DB_USER" -d "$DB_NAME" -c \
    "SELECT COUNT(*) as total_sessions FROM nat_sessions;"

echo ""
echo "==================================================="
echo "✓ Deployment Complete!"
echo "==================================================="
echo ""
echo "Monitoring commands:"
echo "  UDM logs:        ssh -i ~/.ssh/udm_key root@$UDM_HOST 'tail -f /var/log/messages | grep NAT-Logger'"
echo "  Pi syslog:       tail -f /home/admin/bf-network/syslog-container/logs/remote-syslog.log"
echo "  Parser logs:     docker logs -f nat-parser"
echo "  Parser status:   docker compose -f captive-portal/docker-compose.yml ps nat-parser"
echo ""
echo "Database queries:"
echo "  Active sessions:   SELECT * FROM nat_active_sessions;"
echo "  Stats by IP:       SELECT * FROM nat_session_stats_by_ip;"
echo "  Recent sessions:   SELECT * FROM nat_sessions ORDER BY session_end DESC LIMIT 10;"
echo ""
