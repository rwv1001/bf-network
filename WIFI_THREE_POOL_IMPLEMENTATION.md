# WiFi Captive Portal - Three-Pool Implementation Summary

## Overview

Implemented a DHCP-based captive portal for WiFi registration using Kea DHCP with a three-pool architecture. This avoids the complexity of WPA Enterprise while providing dynamic network access control.

## Problem Solved

**Challenge**: WPA2/3 Enterprise with RADIUS CoA is too complex for non-technical users (requires certificate management, complex setup).

**Solution**: Use SSID-based VLAN assignment + DHCP pool management with short leases for quick registration feedback.

## Architecture

### Three DHCP Pools Per VLAN

1. **Registered** (.5-.127)
   - 24-hour lease
   - Public DNS (8.8.8.8)
   - Full internet access
   - Managed via Kea host reservations

2. **Newly Unregistered** (.128-.191)
   - 60-second lease (T1=30s for quick renewal)
   - Portal DNS (192.168.X.4)
   - Walled garden (portal access only)
   - Automatic pool for first-time devices

3. **Old Unregistered** (.192-.254)
   - 24-hour lease (reduces DHCP traffic)
   - Portal DNS (192.168.X.4)
   - Walled garden (portal access only)
   - For devices >30 min old without registration

### Why Short Leases?

**DHCP Renewal Reality**: Clients won't renew before T1 (halfway through lease time). We can't force immediate renewal.

**Solution**: 60-second leases for new devices means they'll naturally renew ~30 seconds after registration approval, providing quick user feedback.

## Implementation Files

### 1. Database Model Updates
**File**: `/home/admin/bf-network/captive-portal/app/models.py`

**Changes**:
- Added `first_seen` timestamp to `Device` model
- Added `get_pool_assignment()` method to determine pool based on age and status
- Imported `timedelta` for time calculations

**SQL Migration**:
```sql
ALTER TABLE devices ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW();
CREATE INDEX IF NOT EXISTS idx_devices_first_seen ON devices(first_seen);
UPDATE devices SET first_seen = COALESCE(registered_at, NOW()) WHERE first_seen IS NULL;
```

### 2. Kea Integration Module
**File**: `/home/admin/bf-network/captive-portal/app/kea_integration.py`

**Key Functions**:
- `register_mac(mac, vlan, hostname, ip)`: Create host reservation for approved devices
- `unregister_mac(mac, vlan)`: Remove host reservation
- `get_lease_by_mac(mac)`: Query current lease info
- `force_lease_renewal(mac)`: Delete lease to trigger immediate renewal

**Communication**: Via Kea control socket (`/tmp/kea-dhcp4.sock`)

### 3. Kea Configuration
**File**: `/home/admin/bf-network/kea/config/dhcp4-simple-pools.json`

**Features**:
- Three IP pools per subnet with appropriate ranges
- Control socket enabled for API access
- Host reservations database for registered devices
- Hook libraries for lease/host management

**Example Pool Configuration** (VLAN 99):
```json
{
  "id": 99,
  "subnet": "192.168.99.0/24",
  "pools": [
    {"pool": "192.168.99.5 - 192.168.99.127"},      // Registered
    {"pool": "192.168.99.128 - 192.168.99.191"},    // Newly Unregistered
    {"pool": "192.168.99.192 - 192.168.99.254"}     // Old Unregistered
  ]
}
```

### 4. Synchronization Service
**File**: `/home/admin/bf-network/kea/scripts/kea-sync.py`

**Purpose**: Daemon that syncs database state to Kea reservations every 60 seconds

**Logic**:
- Query all devices from PostgreSQL
- For each approved device: Create Kea host reservation
- For unapproved devices: Remove any existing reservations
- Updates ensure newly approved devices get proper pool assignment

**Deployment**:
```bash
# Install as systemd service
sudo systemctl enable kea-sync
sudo systemctl start kea-sync
sudo systemctl status kea-sync
```

### 5. Shell Script (Alternative)
**File**: `/home/admin/bf-network/kea/scripts/pool-assignment.sh`

Kea hook script for dynamic pool assignment (alternative implementation if hooks are used).

### 6. Implementation Guide
**File**: `/home/admin/bf-network/kea/KEA_THREE_POOL_GUIDE.md`

Complete deployment and troubleshooting documentation.

### 7. Design Documentation
**File**: `/home/admin/bf-network/captive-portal/WIFI_REGISTRATION_DESIGN.md`

Updated with three-pool architecture details.

## Registration Flow

### Step 1: Initial Connection
```
User connects to WiFi SSID
    ↓
Switch assigns VLAN based on SSID
    ↓
Device sends DHCP DISCOVER
    ↓
Kea checks: No host reservation found
    ↓
Assigns IP from .128-.191 (newly unregistered)
    ↓
60-second lease, DNS=192.168.X.4
```

### Step 2: Portal Access
```
Device tries to access internet
    ↓
Portal DNS redirects to 192.168.X.4:8080/portal
    ↓
Browser opens captive portal
    ↓
User fills registration form (email, name)
    ↓
Clicks Submit
```

### Step 3: Portal Processing
```
Portal receives form
    ↓
Creates/updates Device record (first_seen=NOW, status=pending)
    ↓
Creates RegistrationRequest record
    ↓
Sends email to admin (guest master)
    ↓
Sends confirmation email to user (with unregister link)
    ↓
Shows "Activating..." progress bar (30s max)
```

### Step 4: Admin Approval
```
Admin clicks approval link
    ↓
Portal updates: registration_status='approved'
    ↓
kea_integration.register_mac() called
    ↓
Creates Kea host reservation (.5-.127 range)
    ↓
DNS override to 8.8.8.8
```

### Step 5: Automatic Renewal
```
Device's 60s lease reaches T1 (~30 seconds)
    ↓
Device sends DHCP REQUEST
    ↓
Kea finds host reservation
    ↓
Assigns IP from registered pool (.5-.127)
    ↓
Sets DNS to 8.8.8.8
    ↓
24-hour lease granted
```

### Step 6: User Feedback
```
Frontend JavaScript polls for connectivity
    ↓
Detects public DNS/internet access
    ↓
Progress bar completes → "Connected!"
    ↓
User has full internet access
```

## Unregistration Flow

### Email Link Method
```
User clicks unregister link from email
    ↓
Portal validates token
    ↓
Updates: registration_status='unregistered'
    ↓
kea_integration.unregister_mac() called
    ↓
Removes Kea host reservation
    ↓
Next DHCP renewal → Device gets .192-.254 IP
    ↓
Walled garden access only
```

### MAC Blocking (HP5130 Alternative)
**File**: Future implementation for `/home/admin/bf-network/captive-portal/app/hp5130_integration.py`

```
User clicks unregister link
    ↓
Portal connects to HP5130 via SSH
    ↓
Adds MAC to ACL deny list
    ↓
Device loses network access immediately
```

## Pool Aging Mechanism

### Handled by kea-sync.py

```python
def determine_pool(device):
    if device['status'] == 'approved':
        return 'registered'
    
    if device['age_seconds'] < 1800:  # 30 minutes
        return 'newly_unregistered'
    else:
        return 'old_unregistered'
```

**Automatic Transition**: After 30 minutes without registration, devices naturally move from .128-.191 to .192-.254 range on their next renewal, reducing DHCP traffic.

## Deployment Steps

### 1. Database Migration
```bash
cd /home/admin/bf-network/captive-portal
docker compose exec db psql -U captive_user -d captive_portal <<EOF
ALTER TABLE devices ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW();
CREATE INDEX IF NOT EXISTS idx_devices_first_seen ON devices(first_seen);
UPDATE devices SET first_seen = COALESCE(registered_at, NOW()) WHERE first_seen IS NULL;
EOF
```

### 2. Update Kea Configuration
```bash
cd /home/admin/bf-network/kea
cp config/dhcp4-simple-pools.json config/dhcp4.json
docker compose restart kea-dhcp4
```

### 3. Install Python Dependencies
```bash
pip3 install psycopg2-binary requests
```

### 4. Configure kea-sync Service
```bash
cd /home/admin/bf-network/kea/scripts
chmod +x kea-sync.py

# Create systemd service
sudo tee /etc/systemd/system/kea-sync.service > /dev/null <<'EOF'
[Unit]
Description=Kea DHCP Synchronization Service
After=network.target postgresql.service docker.service

[Service]
Type=simple
User=admin
WorkingDirectory=/home/admin/bf-network/kea/scripts
Environment="DB_HOST=127.0.0.1"
Environment="POSTGRES_DB=captive_portal"
Environment="POSTGRES_USER=captive_user"
Environment="POSTGRES_PASSWORD=<your_password>"
Environment="KEA_CONTROL_SOCKET=/tmp/kea-dhcp4.sock"
Environment="SYNC_INTERVAL=60"
ExecStart=/usr/bin/python3 /home/admin/bf-network/kea/scripts/kea-sync.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kea-sync
sudo systemctl start kea-sync
```

### 5. Update Flask App Integration
In `/home/admin/bf-network/captive-portal/app/app.py`:

```python
from kea_integration import KeaIntegration

kea = KeaIntegration(control_socket='/tmp/kea-dhcp4.sock')

# In admin approval route:
@app.route('/admin/approve/<int:request_id>')
@login_required
def approve_request(request_id):
    req = RegistrationRequest.query.get_or_404(request_id)
    
    # ... existing logic ...
    
    # Register in Kea
    if kea.register_mac(
        mac=device.mac_address,
        vlan=device.current_vlan or 99,
        hostname=f"{req.first_name.lower()}-{req.last_name.lower()}"
    ):
        device.registration_status = 'approved'
        req.status = 'approved'
        db.session.commit()
        flash('Device registered successfully!', 'success')
    else:
        flash('Kea registration failed - check logs', 'error')
```

### 6. Restart Captive Portal
```bash
cd /home/admin/bf-network/captive-portal
docker compose restart web
```

## Testing

### 1. Test Newly Unregistered Pool
```bash
# Connect new device to WiFi
# Verify IP in .128-.191 range
# Verify 60-second lease time
# Check portal accessibility
```

### 2. Test Registration
```bash
# Submit registration form
# Check admin email received
# Admin approves via link
# Watch kea-sync logs: journalctl -u kea-sync -f
# Verify host reservation created
```

### 3. Test Lease Renewal
```bash
# Wait up to 60 seconds
# Device should renew and get .5-.127 IP
# Verify DNS is 8.8.8.8
# Test internet connectivity
```

### 4. Test Pool Aging
```bash
# Leave device unregistered for 30+ minutes
# Should move to .192-.254 range
# Lease should be 24 hours
```

### 5. Test Unregistration
```bash
# Click unregister link from email
# Verify host reservation removed
# Next renewal should give .192-.254 IP
# Verify walled garden active
```

## Monitoring

### Check kea-sync Status
```bash
sudo systemctl status kea-sync
sudo journalctl -u kea-sync -f
```

### Query Kea Reservations
```bash
docker compose -f /home/admin/bf-network/kea/docker-compose.yml exec kea-dhcp4 sh -c "echo '{\"command\":\"reservation-get-all\",\"service\":[\"dhcp4\"],\"arguments\":{\"subnet-id\":99}}' | socat - UNIX-CONNECT:/tmp/kea-dhcp4.sock"
```

### Check Lease Database
```bash
docker compose -f /home/admin/bf-network/kea/docker-compose.yml exec kea-dhcp4 cat /kea/leases/kea-leases4.csv
```

### Query Device Pool Assignments
```bash
docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml exec db psql -U captive_user -d captive_portal -c "SELECT mac_address, registration_status, first_seen, EXTRACT(EPOCH FROM (NOW() - first_seen)) AS age_seconds FROM devices ORDER BY first_seen DESC LIMIT 20;"
```

## Network Configuration Requirements

### DHCP Snooping (HP5130)
Must be enabled to prevent manual IP assignment bypass:
```
dhcp snooping enable
dhcp snooping vlan 10 20 30 40 50 60 70 99
```

### DNS Redirection (Pi/dnsmasq)
For unregistered devices (DNS=192.168.X.4):
```
# In dnsmasq.conf
address=/#/192.168.X.4
```

### Firewall Rules
Allow portal access, block internet for .128-.254 ranges:
```bash
# Unregistered: portal only
iptables -A FORWARD -s 192.168.X.128/26 -d 192.168.X.4 -j ACCEPT
iptables -A FORWARD -s 192.168.X.128/26 -j DROP

iptables -A FORWARD -s 192.168.X.192/26 -d 192.168.X.4 -j ACCEPT
iptables -A FORWARD -s 192.168.X.192/26 -j DROP

# Registered: full access
iptables -A FORWARD -s 192.168.X.5/25 -j ACCEPT
```

## Advantages

✅ **User-friendly**: Simple WiFi password, no certificates or complex setup
✅ **Fast feedback**: 30-60 second activation time after approval
✅ **Efficient**: Reduced DHCP traffic after 30 min aging
✅ **Scalable**: Works across multiple VLANs/SSIDs
✅ **Secure**: MAC registration, DHCP snooping prevents spoofing
✅ **Self-service**: Email-based unregistration
✅ **Auditable**: Full database tracking of registrations

## Future Enhancements

1. **HP5130 MAC Blocking**: Implement SSH/SNMP integration for immediate unregistration
2. **Frontend Timer**: JavaScript progress bar during activation period
3. **Email Templates**: Branded registration confirmation emails
4. **Auto-cleanup**: Remove old devices after X days inactive
5. **Dashboard**: Real-time pool utilization statistics
6. **Multi-SSID**: Per-SSID registration requirements
7. **Bandwidth Limits**: QoS for unregistered vs registered

## Related Documentation

- `/home/admin/bf-network/kea/KEA_THREE_POOL_GUIDE.md` - Detailed Kea setup guide
- `/home/admin/bf-network/captive-portal/WIFI_REGISTRATION_DESIGN.md` - Architecture documentation
- `/home/admin/bf-network/captive-portal/DEPLOYMENT_CHECKLIST.md` - Deployment steps
- `/home/admin/bf-network/SYSTEM_OVERVIEW.md` - Overall network architecture
