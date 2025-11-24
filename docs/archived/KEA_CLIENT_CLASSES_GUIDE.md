# Kea Client Classes Implementation Guide

## Overview

This implementation uses **Kea client classes with expression evaluation** to assign devices to different IP pools based on their registration status. This approach:

- ✅ Works within Docker containers
- ✅ No external scripts or databases required
- ✅ Simple configuration using Kea's built-in expression language
- ✅ Evaluates `user-context` field in host reservations

## Architecture

### Client Classes

**Two client classes defined:**

1. **REGISTERED** - Devices with approved registrations
   - Test expression: Checks if host reservation has `user-context.registered == true`
   - Pool: `.5 - .127` (123 IPs per VLAN)
   - DNS: `8.8.8.8, 8.8.4.4` (public DNS - full internet)
   - Lease: 24 hours

2. **UNREGISTERED** - Devices without reservations
   - Test expression: `not member('REGISTERED')`
   - Pool: `.128 - .254` (127 IPs per VLAN)
   - DNS: `192.168.99.4` (portal - walled garden)
   - Lease: Default (24 hours, can be reduced)

### How It Works

```
┌─────────────────────────────────────────────────────┐
│ Device requests DHCP lease                          │
└─────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│ Kea checks: Does MAC have host reservation?        │
└─────────────────────────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
         YES                     NO
          │                       │
          ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│ Has user-context │    │ Assign           │
│ .registered=true?│    │ UNREGISTERED     │
└──────────────────┘    │ class            │
          │             └──────────────────┘
      ┌───┴───┐                 │
     YES     NO                 │
      │       │                 │
      ▼       ▼                 ▼
┌──────────┐ ┌──────────────────┐
│ REGISTERED│ │  UNREGISTERED    │
│ class    │ │  class           │
└──────────┘ └──────────────────┘
      │             │
      ▼             ▼
┌──────────┐ ┌──────────────────┐
│ Pool:    │ │ Pool:            │
│ .5-.127  │ │ .128-.254        │
│ DNS:     │ │ DNS:             │
│ 8.8.8.8  │ │ 192.168.99.4     │
│ 24h lease│ │ 24h lease        │
└──────────┘ └──────────────────┘
```

## Registration Flow

### 1. Initial Connection (Unregistered Device)

```bash
# Device connects to WiFi SSID → VLAN 40
# No host reservation exists
# Kea assigns: UNREGISTERED class
# IP: 192.168.40.128 - .254
# DNS: 192.168.99.4 (portal)
# User sees captive portal
```

### 2. User Registers on Portal

```python
# Portal receives registration
# Calls kea_integration.register_mac()
# Creates host reservation with user-context:
{
  "hw-address": "aa:bb:cc:dd:ee:ff",
  "user-context": {
    "registered": true,
    "registered-at": "2025-11-16T10:30:00Z"
  }
}
```

### 3. DHCP Lease Renewal

```bash
# Device lease renews (T1 timer)
# Kea evaluates client class expression
# Finds reservation with registered=true
# Assigns: REGISTERED class
# IP: 192.168.40.5 - .127
# DNS: 8.8.8.8 (public DNS)
# Full internet access!
```

### 4. User Unregisters

```python
# User clicks unregister link in email
# Portal calls kea_integration.unregister_mac()
# Deletes host reservation
# Next DHCP renewal → UNREGISTERED class
# Back to walled garden
```

## Configuration Files

### Kea Configuration
**File:** `/home/admin/bf-network/kea/config/dhcp4-client-classes.json`

Key sections:

```json
{
  "client-classes": [
    {
      "name": "REGISTERED",
      "test": "pkt.reserved('user-context') and pkt.reserved('user-context').contains('registered') and pkt.reserved('user-context').get('registered') == true",
      "option-data": [
        { "name": "domain-name-servers", "data": "8.8.8.8, 8.8.4.4" }
      ]
    },
    {
      "name": "UNREGISTERED",
      "test": "not member('REGISTERED')",
      "option-data": [
        { "name": "domain-name-servers", "data": "192.168.99.4" }
      ]
    }
  ],
  
  "subnet4": [
    {
      "subnet": "192.168.40.0/24",
      "pools": [
        {
          "pool": "192.168.40.5 - 192.168.40.127",
          "client-class": "REGISTERED"
        },
        {
          "pool": "192.168.40.128 - 192.168.40.254",
          "client-class": "UNREGISTERED"
        }
      ]
    }
  ]
}
```

### Control Socket Configuration

```json
{
  "control-socket": {
    "socket-type": "unix",
    "socket-name": "/kea/leases/kea4-ctrl-socket"
  }
}
```

### Docker Volume Mounts

**Kea container** (`kea/docker-compose.yml`):
```yaml
volumes:
  - ./leases:/kea/leases  # Socket accessible here
```

**Portal container** (`captive-portal/docker-compose.yml`):
```yaml
volumes:
  - ../kea/leases:/kea/leases:ro  # Read-only access to socket
```

## Portal Integration

### Environment Variables

Add to `captive-portal/.env`:
```bash
KEA_CONTROL_SOCKET=/kea/leases/kea4-ctrl-socket
```

### Python Code

```python
from kea_integration import get_kea_client

# Initialize Kea client
kea = get_kea_client(control_socket=os.getenv('KEA_CONTROL_SOCKET'))

# Register device
kea.register_mac(
    mac='aa:bb:cc:dd:ee:ff',
    vlan=40,
    hostname='johns-laptop'
)

# Unregister device
kea.unregister_mac(
    mac='aa:bb:cc:dd:ee:ff',
    vlan=40
)
```

## Expression Language Reference

### Available Functions

- `pkt.reserved(field)` - Get field from host reservation
- `.contains(key)` - Check if dict contains key
- `.get(key)` - Get value from dict
- `member(class)` - Check if already assigned to class
- `not expression` - Boolean negation

### Expression Examples

**Check if registered:**
```
pkt.reserved('user-context') and 
pkt.reserved('user-context').contains('registered') and 
pkt.reserved('user-context').get('registered') == true
```

**Check if NOT registered:**
```
not member('REGISTERED')
```

**Check specific VLAN in user-context:**
```
pkt.reserved('user-context') and
pkt.reserved('user-context').get('vlan') == 40
```

## Testing

### 1. Test Unregistered Device

```bash
# From a device on VLAN 40 (not registered)
sudo dhclient -r eth0  # Release
sudo dhclient -v eth0  # Renew

# Check assigned IP
ip addr show eth0
# Should be in range 192.168.40.128 - .254

# Check DNS
nmcli dev show eth0 | grep DNS
# Should be 192.168.99.4
```

### 2. Test Registration

```bash
# Register via portal
curl -X POST http://192.168.99.4:8080/register \
  -d "email=test@example.com" \
  -d "first_name=Test" \
  -d "last_name=User"

# Wait for DHCP renewal (or force it)
sudo dhclient -r eth0 && sudo dhclient -v eth0

# Check new IP
ip addr show eth0
# Should be in range 192.168.40.5 - .127

# Check DNS
nmcli dev show eth0 | grep DNS
# Should be 8.8.8.8, 8.8.4.4

# Test internet
ping -c 3 8.8.8.8
```

### 3. Verify Kea State

```bash
# Check reservations
docker exec kea kea-shell --host localhost --port 8000 \
  reservation-get-all --subnet-id 40

# Check leases
docker exec kea cat /kea/leases/kea-leases4.csv | grep aa:bb:cc:dd:ee:ff

# Check stats
docker exec kea kea-shell --host localhost --port 8000 statistic-get-all
```

## Advantages of This Approach

✅ **Simple**: No external databases or scripts
✅ **Fast**: Expression evaluation is in-memory
✅ **Portable**: Works in Docker without complex networking
✅ **Maintainable**: All logic in one Kea config file
✅ **Reliable**: Uses Kea's built-in features (well-tested)
✅ **Flexible**: Easy to add more client classes or conditions

## Limitations

⚠️ **Lease renewal timing**: Devices won't get new pool until T1 (renewal time)
   - For 24h lease: T1 = 12 hours
   - Workaround: Portal shows "wait 30 seconds" progress bar
   - Alternative: Reduce lease time to 1 hour (T1 = 30 min)

⚠️ **No lease forcing**: Can't force client to renew early
   - DHCP protocol limitation (client controls renewal)
   - Portal can delete old lease, but client must discover this

## Troubleshooting

### Device not getting registered pool

1. Check reservation exists:
   ```bash
   docker exec kea kea-shell reservation-get \
     --subnet-id 40 --identifier-type hw-address \
     --identifier aa:bb:cc:dd:ee:ff
   ```

2. Check user-context is correct:
   ```json
   {
     "user-context": {
       "registered": true
     }
   }
   ```

3. Force DHCP renewal on device

### DNS not changing

1. Check pool assignment (IP should be in .5-.127 range)
2. Verify client class assignment in Kea logs:
   ```bash
   docker logs kea | grep "aa:bb:cc:dd:ee:ff"
   ```

3. Check device DNS cache:
   ```bash
   sudo systemd-resolve --flush-caches  # Linux
   ```

### Control socket not accessible

1. Check socket exists:
   ```bash
   ls -la /home/admin/bf-network/kea/leases/kea4-ctrl-socket
   ```

2. Check permissions:
   ```bash
   chmod 666 /home/admin/bf-network/kea/leases/kea4-ctrl-socket
   ```

3. Verify Docker volume mounts in both containers

## Next Steps

1. ✅ Update `captive-portal/docker-compose.yml` to mount Kea socket
2. ✅ Update `captive-portal/.env` with `KEA_CONTROL_SOCKET` path
3. ✅ Modify `app.py` to use `kea_integration` for WiFi registrations
4. ✅ Add database fields: `connection_type`, `ssid`, `first_seen`, `unregister_token`
5. ✅ Create unregister endpoint and email template
6. Test complete flow with real device
7. Adjust lease times based on testing results
8. Configure firewall rules for walled garden (unregistered pool)
