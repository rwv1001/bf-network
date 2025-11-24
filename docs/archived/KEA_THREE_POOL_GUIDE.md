# Kea DHCP Three-Pool Implementation Guide

## Overview

This implementation uses three DHCP pools to support the captive portal registration flow:

1. **Registered Pool** (.5-.127): Approved devices with full internet access (24h lease, public DNS 8.8.8.8)
2. **Newly Unregistered Pool** (.128-.191): First-time devices (<30 min old) with short leases (60s) for quick registration feedback
3. **Old Unregistered Pool** (.192-.254): Long-term unregistered devices (>30 min old) with 24h leases to reduce DHCP traffic

## Architecture

### Pool Assignment Strategy

The three-pool approach solves the DHCP lease renewal problem:
- **Problem**: DHCP clients won't renew before T1 (half the lease time), so we can't force immediate renewal after registration
- **Solution**: Give new devices very short leases (60 seconds), so they naturally renew within 30 seconds of registration

### Implementation Approach

We use **two complementary mechanisms**:

#### 1. Host Reservations (Kea Control Socket)
- Registered devices get host reservations with:
  - IP from registered pool (.5-.127)
  - DNS override to public DNS (8.8.8.8)
  - 24h lease time
  - Hostname based on user info

#### 2. Pool Assignment by IP Range
- Kea automatically assigns IPs from different pools based on availability
- New devices get IPs from .128-.191 (newly unregistered) or .192-.254 (old unregistered)
- The `kea-sync.py` service manages pool transitions:
  - Newly registered: Creates host reservation → device moves to .5-.127 on next renewal
  - Aging out (30 min): Device moves from .128-.191 to .192-.254 naturally

## Files

### 1. Kea Configuration: `/home/admin/bf-network/kea/config/dhcp4-simple-pools.json`

Simple configuration with three IP pools per subnet. No complex client classes needed.

**Key features:**
- Control socket enabled at `/tmp/kea-dhcp4.sock` for dynamic management
- Host reservations stored in `/kea/data/kea-reservations.json`
- Hook libraries for lease and host management
- Three pools per subnet with appropriate ranges

### 2. Sync Service: `/home/admin/bf-network/kea/scripts/kea-sync.py`

Python daemon that synchronizes database state with Kea reservations.

**What it does:**
- Runs every 60 seconds (configurable)
- Queries PostgreSQL for all devices
- For each device:
  - **Approved (registered_status='approved')**: Creates host reservation in registered pool
  - **First seen <30 min**: No reservation needed, gets short lease from .128-.191
  - **First seen >30 min**: No reservation needed, gets long lease from .192-.254

**How to run:**
```bash
cd /home/admin/bf-network/kea/scripts
chmod +x kea-sync.py

# Environment variables
export DB_HOST=127.0.0.1
export POSTGRES_DB=captive_portal
export POSTGRES_USER=captive_user
export POSTGRES_PASSWORD=your_password
export KEA_CONTROL_SOCKET=/tmp/kea-dhcp4.sock
export SYNC_INTERVAL=60

# Run as service
python3 kea-sync.py
```

### 3. Integration Module: `/home/admin/bf-network/captive-portal/app/kea_integration.py`

Python module for Flask app to interact with Kea.

**Key functions:**
- `register_mac(mac, vlan, hostname, ip)`: Add host reservation for approved device
- `unregister_mac(mac, vlan)`: Remove host reservation
- `get_lease_by_mac(mac)`: Check current lease info
- `force_lease_renewal(mac)`: Delete lease to trigger renewal

### 4. Database Model: `/home/admin/bf-network/captive-portal/app/models.py`

Updated Device model with:
- `first_seen`: Timestamp when MAC first appeared (for pool age calculation)
- `get_pool_assignment()`: Method to determine pool based on registration status and age

## Registration Flow

### Initial Connection (Newly Unregistered)

1. User connects to WiFi SSID → Switch assigns VLAN based on SSID
2. Device requests DHCP → Kea assigns from .128-.191 (60s lease)
3. Device has portal DNS (192.168.X.4) → Captive portal detection triggers
4. Browser opens portal registration page

### Registration Submission

1. User fills form → Portal creates `RegistrationRequest` and `Device` entry
2. Device record has `first_seen=NOW()`, `registration_status='pending'`
3. Email sent to admin for approval
4. Confirmation email sent to user with unregister link

### Admin Approval

1. Admin clicks approval link
2. Portal updates `registration_status='approved'`
3. **Kea integration: `kea_integration.register_mac()`**
   - Creates host reservation for device
   - IP allocated from registered pool (.5-.127)
   - DNS set to public (8.8.8.8)
4. User sees "Activating..." progress bar (30s max)

### Lease Renewal (Within 30-60 seconds)

1. Device's 60s lease reaches T1 (~30s) → Sends DHCP REQUEST
2. Kea sees host reservation → Assigns IP from registered pool (.5-.127)
3. Device gets public DNS → Full internet access
4. Frontend JavaScript detects connectivity → "Connected!"

### After 30 Minutes (Aging Out)

If device not registered after 30 minutes:
1. `kea-sync.py` sees `first_seen > 30 min ago`
2. No action needed - device naturally moves to .192-.254 range on next renewal
3. Lease time increases to 24h to reduce DHCP traffic

## Deployment

### 1. Update Kea Configuration

```bash
cd /home/admin/bf-network/kea
cp config/dhcp4-simple-pools.json config/dhcp4.json

# Restart Kea
cd /home/admin/bf-network/kea
docker compose restart
```

### 2. Apply Database Migration

```bash
# Add first_seen column to devices table
docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml exec db psql -U captive_user -d captive_portal -c "ALTER TABLE devices ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW();"
docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml exec db psql -U captive_user -d captive_portal -c "CREATE INDEX IF NOT EXISTS idx_devices_first_seen ON devices(first_seen);"
docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml exec db psql -U captive_user -d captive_portal -c "UPDATE devices SET first_seen = COALESCE(registered_at, NOW()) WHERE first_seen IS NULL;"
```

### 3. Start Kea Sync Service

```bash
cd /home/admin/bf-network/kea/scripts
chmod +x kea-sync.py

# Install dependencies
pip3 install psycopg2-binary requests

# Create systemd service (optional)
sudo tee /etc/systemd/system/kea-sync.service > /dev/null <<EOF
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
Environment="POSTGRES_PASSWORD=your_password"
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

### 4. Update Flask App

The Flask app already has the integration code. Just ensure the `kea_integration.py` module is imported in `app.py`:

```python
from kea_integration import KeaIntegration

kea = KeaIntegration(control_socket='/tmp/kea-dhcp4.sock')

# In approval route:
if kea.register_mac(device.mac_address, device.current_vlan or 99):
    device.registration_status = 'approved'
    db.session.commit()
```

## Testing

### 1. Test Newly Unregistered Pool

```bash
# Connect new device to WiFi
# Check it gets IP in .128-.191 range with 60s lease
docker compose -f /home/admin/bf-network/kea/docker-compose.yml logs -f
```

### 2. Test Registration Flow

```bash
# Register device through portal
# Watch kea-sync.py logs
journalctl -u kea-sync -f

# Verify host reservation created
docker compose -f /home/admin/bf-network/kea/docker-compose.yml exec kea-dhcp4 kea-shell --host 127.0.0.1 --port 8000
> reservation-get subnet-id 99 identifier-type hw-address identifier aa:bb:cc:dd:ee:ff
```

### 3. Test Lease Renewal

```bash
# Wait up to 60 seconds
# Device should get new IP from .5-.127 range
# Check DNS is now 8.8.8.8
```

### 4. Test Aging Out

```bash
# Wait 30 minutes without registering
# Device should move to .192-.254 range
# Lease should increase to 24h
```

## Troubleshooting

### Device not getting short lease

- Check Kea logs: `docker compose -f /home/admin/bf-network/kea/docker-compose.yml logs kea-dhcp4`
- Verify pools are configured correctly
- Check device is not already in reservations

### Registration not taking effect

- Check kea-sync.py is running: `systemctl status kea-sync`
- Verify database has `first_seen` column
- Check host reservation was created (use kea-shell)

### Device stuck in unregistered pool

- Check kea-sync.py logs for errors
- Verify PostgreSQL connection working
- Manually check device.registration_status in database

## Future Enhancements

1. **Dynamic lease adjustment**: Implement hook to automatically adjust lease time based on pool
2. **Lease statistics**: Add dashboard showing pool utilization
3. **Auto-cleanup**: Remove old unregistered devices after X days
4. **IP allocation optimization**: Smart IP assignment to avoid fragmentation
