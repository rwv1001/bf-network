# FreeRADIUS Configuration for Captive Portal Integration

## Overview

This configuration update enables FreeRADIUS to work with the captive portal by:
1. Accepting Change-of-Authorization (CoA) requests from the portal
2. Allowing the portal to dynamically change device VLANs
3. Supporting device disconnection requests

## Changes Made

### 1. CoA Server Configuration

**File: `raddb/sites-available/coa`**
- Created CoA server listening on port 3799
- Handles CoA and Disconnect requests
- Logs all CoA operations

### 2. Client Configuration

**File: `raddb/clients.conf`**
- Added captive-portal as a RADIUS client
- IP: 192.168.99.4 (your Pi)
- Secret: testing123 (change in production!)
- Enabled CoA capability

### 3. Docker Compose Updates

**File: `docker-compose.yml`**
- Mounted CoA site configuration files
- Enabled CoA site

## Testing CoA

### 1. Check FreeRADIUS is accepting CoA

```bash
# Restart FreeRADIUS with new config
cd /home/admin/bf-network/freeradius
docker-compose restart

# Check logs
docker-compose logs -f
# Should see: "Listening on coa address * port 3799"
```

### 2. Test CoA from command line

```bash
# Install radclient if not available
sudo apt-get install freeradius-utils

# Test CoA packet
echo "Calling-Station-Id = \"aa:bb:cc:dd:ee:ff\"" | \
  radclient -x 192.168.99.4:3799 coa testing123
```

### 3. Test from captive portal

The portal automatically sends CoA when:
- User completes registration
- Admin approves a request
- Admin changes user status
- Admin disconnects a device

Check portal logs:
```bash
cd /home/admin/bf-network/captive-portal
docker-compose logs -f web | grep CoA
```

## Security Considerations

### Change the RADIUS Secret

The default secret is `testing123`. For production:

1. Generate a strong secret:
   ```bash
   openssl rand -base64 32
   ```

2. Update in **two places**:
   - `freeradius/raddb/clients.conf` (coa_secret)
   - `captive-portal/.env` (RADIUS_SECRET)

3. Restart both services:
   ```bash
   docker-compose -f freeradius/docker-compose.yml restart
   docker-compose -f captive-portal/docker-compose.yml restart
   ```

### Restrict CoA Client IP

In production, restrict the captive-portal client to specific IP:

```
client captive-portal {
  ipaddr = 192.168.99.4/32
  ...
}
```

## CoA Packet Flow

```
Captive Portal                    FreeRADIUS                    HP5130
     |                                |                            |
     | 1. Send CoA-Request            |                            |
     |   (MAC, new VLAN)              |                            |
     |------------------------------->|                            |
     |                                |                            |
     |                                | 2. Forward CoA to NAS      |
     |                                |--------------------------->|
     |                                |                            |
     |                                |                            | 3. Disconnect device
     |                                |                            | 4. Device reconnects
     |                                |                            | 5. MAC auth request
     |                                |<---------------------------|
     |                                |                            |
     |                                | 6. Auth reply (new VLAN)   |
     |                                |--------------------------->|
     |                                |                            |
     | 7. CoA-ACK                     |                            |
     |<-------------------------------|                            |
```

## Troubleshooting

### CoA not working

1. **Check FreeRADIUS is listening on port 3799:**
   ```bash
   netstat -uln | grep 3799
   ```

2. **Check client configuration:**
   ```bash
   docker-compose -f freeradius/docker-compose.yml exec freeradius \
     radiusd -XC | grep captive-portal
   ```

3. **Check secret matches:**
   - In `freeradius/raddb/clients.conf`: `secret = testing123`
   - In `captive-portal/.env`: `RADIUS_SECRET=testing123`

4. **Check firewall:**
   ```bash
   # Allow CoA port
   sudo ufw allow 3799/udp
   ```

5. **Check logs:**
   ```bash
   # FreeRADIUS logs
   docker-compose -f freeradius/docker-compose.yml logs -f | grep -i coa
   
   # Portal logs
   docker-compose -f captive-portal/docker-compose.yml logs -f | grep -i coa
   ```

### Device not moving to new VLAN

1. **Check switch supports CoA:**
   - HP5130 supports CoA (confirmed in your config)
   - Ensure CoA is enabled on switch

2. **Check NAS IP in CoA packet:**
   - Portal sends `NAS-IP-Address = 192.168.99.1` (your switch)
   - Verify this matches your switch IP

3. **Check MAC address format:**
   - FreeRADIUS expects: `AA-BB-CC-DD-EE-FF` or `AA:BB:CC:DD:EE:FF`
   - Portal normalizes to: `aa:bb:cc:dd:ee:ff`
   - May need adjustment based on your switch

4. **Check VLAN assignment:**
   - Verify VLAN exists on switch
   - Verify port is member of VLAN
   - Check switch logs for CoA receipt

## Alternative: Database Integration

For more advanced integration, you can configure FreeRADIUS to read directly from the captive portal database:

**Benefits:**
- FreeRADIUS always has current device-VLAN mappings
- No need to maintain `authorize` file
- Real-time updates

**Implementation:**
1. Install PostgreSQL module in FreeRADIUS
2. Configure SQL queries to read from portal DB
3. Update sites-enabled/default to use SQL

See FreeRADIUS SQL documentation for details.

## Next Steps

1. **Test the configuration:**
   - Register a device via portal
   - Verify CoA succeeds
   - Confirm device moves to correct VLAN

2. **Monitor in production:**
   - Watch FreeRADIUS logs for CoA
   - Monitor portal logs for errors
   - Check switch logs for VLAN changes

3. **Document your setup:**
   - Note any customizations
   - Record RADIUS secrets (securely!)
   - Document troubleshooting steps

4. **Consider automation:**
   - Script to sync portal DB to authorize file
   - Alerts for CoA failures
   - Dashboard for VLAN assignments
