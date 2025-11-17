#!/bin/bash
#
# Migration Script: Transition to Three-Pool DHCP Architecture
#
# This script migrates from the old DHCP configuration to the new three-pool setup
# for WiFi captive portal registration.
#
# IMPORTANT: Review and test in a non-production environment first!

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Three-Pool DHCP Migration Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Configuration
CAPTIVE_PORTAL_DIR="/home/admin/bf-network/captive-portal"
KEA_DIR="/home/admin/bf-network/kea"
BACKUP_DIR="/home/admin/bf-network-backup-$(date +%Y%m%d-%H%M%S)"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

confirm() {
    read -p "$1 (y/n) " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# Backup existing configuration
backup_config() {
    log_info "Creating backup at $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Backup Kea config
    if [ -d "$KEA_DIR" ]; then
        cp -r "$KEA_DIR/config" "$BACKUP_DIR/kea-config"
        log_info "Backed up Kea configuration"
    fi
    
    # Backup captive portal
    if [ -d "$CAPTIVE_PORTAL_DIR" ]; then
        cp -r "$CAPTIVE_PORTAL_DIR/app" "$BACKUP_DIR/captive-portal-app"
        log_info "Backed up captive portal app"
    fi
    
    # Export database
    if command -v docker &> /dev/null; then
        log_info "Exporting PostgreSQL database..."
        docker compose -f "$CAPTIVE_PORTAL_DIR/docker-compose.yml" exec -T db \
            pg_dump -U captive_user captive_portal > "$BACKUP_DIR/captive_portal.sql"
        log_info "Database backed up to $BACKUP_DIR/captive_portal.sql"
    fi
}

# Step 1: Database migration
migrate_database() {
    log_info "Step 1: Migrating database schema..."
    
    # Add first_seen column
    log_info "Adding first_seen column to devices table..."
    docker compose -f "$CAPTIVE_PORTAL_DIR/docker-compose.yml" exec -T db \
        psql -U captive_user -d captive_portal <<-EOF
            ALTER TABLE devices 
            ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW();
            
            CREATE INDEX IF NOT EXISTS idx_devices_first_seen 
            ON devices(first_seen);
            
            UPDATE devices 
            SET first_seen = COALESCE(registered_at, NOW()) 
            WHERE first_seen IS NULL;
EOF
    
    if [ $? -eq 0 ]; then
        log_info "Database migration completed successfully"
    else
        log_error "Database migration failed"
        return 1
    fi
}

# Step 2: Update Kea configuration
update_kea_config() {
    log_info "Step 2: Updating Kea DHCP configuration..."
    
    if [ -f "$KEA_DIR/config/dhcp4-simple-pools.json" ]; then
        # Backup current config
        if [ -f "$KEA_DIR/config/dhcp4.json" ]; then
            cp "$KEA_DIR/config/dhcp4.json" "$KEA_DIR/config/dhcp4.json.old"
            log_info "Backed up current Kea config to dhcp4.json.old"
        fi
        
        # Copy new config
        cp "$KEA_DIR/config/dhcp4-simple-pools.json" "$KEA_DIR/config/dhcp4.json"
        log_info "Updated Kea configuration to three-pool setup"
        
        # Validate JSON
        if command -v jq &> /dev/null; then
            jq empty "$KEA_DIR/config/dhcp4.json" 2>/dev/null
            if [ $? -eq 0 ]; then
                log_info "Kea configuration JSON is valid"
            else
                log_error "Kea configuration JSON is invalid!"
                return 1
            fi
        else
            log_warn "jq not installed, skipping JSON validation"
        fi
    else
        log_error "Three-pool configuration file not found!"
        return 1
    fi
}

# Step 3: Install Python dependencies
install_dependencies() {
    log_info "Step 3: Installing Python dependencies..."
    
    pip3 install --quiet psycopg2-binary requests 2>/dev/null || \
        pip3 install --user psycopg2-binary requests
    
    if [ $? -eq 0 ]; then
        log_info "Dependencies installed successfully"
    else
        log_warn "Some dependencies may have failed to install"
    fi
}

# Step 4: Setup kea-sync service
setup_kea_sync() {
    log_info "Step 4: Setting up kea-sync systemd service..."
    
    # Make script executable
    chmod +x "$KEA_DIR/scripts/kea-sync.py"
    
    # Get database password
    if [ -f "$CAPTIVE_PORTAL_DIR/.env" ]; then
        DB_PASSWORD=$(grep POSTGRES_PASSWORD "$CAPTIVE_PORTAL_DIR/.env" | cut -d '=' -f2)
    else
        log_warn "Could not find .env file"
        read -sp "Enter PostgreSQL password: " DB_PASSWORD
        echo
    fi
    
    # Create systemd service file
    sudo tee /etc/systemd/system/kea-sync.service > /dev/null <<EOF
[Unit]
Description=Kea DHCP Synchronization Service
After=network.target postgresql.service docker.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$KEA_DIR/scripts
Environment="DB_HOST=127.0.0.1"
Environment="DB_PORT=5432"
Environment="POSTGRES_DB=captive_portal"
Environment="POSTGRES_USER=captive_user"
Environment="POSTGRES_PASSWORD=$DB_PASSWORD"
Environment="KEA_CONTROL_SOCKET=/tmp/kea-dhcp4.sock"
Environment="SYNC_INTERVAL=60"
ExecStart=/usr/bin/python3 $KEA_DIR/scripts/kea-sync.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    sudo systemctl daemon-reload
    log_info "Created kea-sync.service"
}

# Step 5: Restart services
restart_services() {
    log_info "Step 5: Restarting services..."
    
    # Restart Kea
    log_info "Restarting Kea DHCP..."
    docker compose -f "$KEA_DIR/docker-compose.yml" restart kea-dhcp4
    sleep 5
    
    # Start kea-sync
    log_info "Starting kea-sync service..."
    sudo systemctl enable kea-sync
    sudo systemctl start kea-sync
    
    # Restart captive portal (optional, for updated integration code)
    if confirm "Restart captive portal web service?"; then
        log_info "Restarting captive portal..."
        docker compose -f "$CAPTIVE_PORTAL_DIR/docker-compose.yml" restart web
    fi
}

# Step 6: Verification
verify_setup() {
    log_info "Step 6: Verifying setup..."
    
    # Check database column
    log_info "Checking database schema..."
    COLUMN_EXISTS=$(docker compose -f "$CAPTIVE_PORTAL_DIR/docker-compose.yml" exec -T db \
        psql -U captive_user -d captive_portal -t -c \
        "SELECT column_name FROM information_schema.columns WHERE table_name='devices' AND column_name='first_seen';" | xargs)
    
    if [ "$COLUMN_EXISTS" = "first_seen" ]; then
        log_info "✓ Database schema updated"
    else
        log_error "✗ Database schema migration failed"
        return 1
    fi
    
    # Check Kea service
    log_info "Checking Kea DHCP service..."
    if docker compose -f "$KEA_DIR/docker-compose.yml" ps | grep -q "kea-dhcp4.*Up"; then
        log_info "✓ Kea DHCP service is running"
    else
        log_error "✗ Kea DHCP service is not running"
        return 1
    fi
    
    # Check kea-sync service
    log_info "Checking kea-sync service..."
    if sudo systemctl is-active --quiet kea-sync; then
        log_info "✓ kea-sync service is running"
    else
        log_error "✗ kea-sync service is not running"
        return 1
    fi
    
    # Check control socket
    if [ -S "/tmp/kea-dhcp4.sock" ]; then
        log_info "✓ Kea control socket exists"
    else
        log_warn "⚠ Kea control socket not found (may need time to initialize)"
    fi
    
    log_info "Verification complete!"
}

# Step 7: Display status
show_status() {
    echo ""
    log_info "Migration Summary"
    echo "================================================"
    echo ""
    echo "Backup location: $BACKUP_DIR"
    echo ""
    echo "Service Status:"
    echo "  Kea DHCP: $(docker compose -f "$KEA_DIR/docker-compose.yml" ps kea-dhcp4 2>/dev/null | grep -o 'Up' || echo 'Down')"
    echo "  kea-sync: $(sudo systemctl is-active kea-sync 2>/dev/null || echo 'inactive')"
    echo "  Portal:   $(docker compose -f "$CAPTIVE_PORTAL_DIR/docker-compose.yml" ps web 2>/dev/null | grep -o 'Up' || echo 'Down')"
    echo ""
    echo "Useful Commands:"
    echo "  Check kea-sync logs:   sudo journalctl -u kea-sync -f"
    echo "  Check Kea logs:        docker compose -f $KEA_DIR/docker-compose.yml logs -f kea-dhcp4"
    echo "  Restart kea-sync:      sudo systemctl restart kea-sync"
    echo "  View device pools:     docker compose -f $CAPTIVE_PORTAL_DIR/docker-compose.yml exec db \\"
    echo "                         psql -U captive_user -d captive_portal -c \\"
    echo "                         \"SELECT mac_address, registration_status, first_seen FROM devices;\""
    echo ""
    echo "Documentation:"
    echo "  Implementation Guide:  $KEA_DIR/KEA_THREE_POOL_GUIDE.md"
    echo "  Quick Reference:       /home/admin/bf-network/QUICK_REFERENCE.md"
    echo "  Full Summary:          /home/admin/bf-network/WIFI_THREE_POOL_IMPLEMENTATION.md"
    echo ""
    echo -e "${GREEN}Migration completed successfully!${NC}"
    echo ""
}

# Main execution
main() {
    echo ""
    log_warn "This script will migrate your system to the three-pool DHCP architecture."
    log_warn "A backup will be created at: $BACKUP_DIR"
    echo ""
    
    if ! confirm "Do you want to continue?"; then
        log_info "Migration cancelled"
        exit 0
    fi
    
    echo ""
    
    # Run migration steps
    backup_config || { log_error "Backup failed"; exit 1; }
    echo ""
    
    migrate_database || { log_error "Database migration failed"; exit 1; }
    echo ""
    
    update_kea_config || { log_error "Kea configuration update failed"; exit 1; }
    echo ""
    
    install_dependencies
    echo ""
    
    setup_kea_sync || { log_error "kea-sync setup failed"; exit 1; }
    echo ""
    
    restart_services
    echo ""
    
    sleep 5  # Give services time to start
    
    verify_setup || { log_warn "Verification found issues - check logs"; }
    echo ""
    
    show_status
}

# Run main function
main "$@"
