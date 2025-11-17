# WiFi Registration System Design

## Problem Statement

**RADIUS limitations over WiFi:**
- WPA2/3 Personal (PSK): No dynamic VLAN assignment
- WPA2/3 Enterprise: Supports dynamic VLANs but too complex for non-technical users
- CoA doesn't help with PSK-based WiFi

## Solution: Hybrid Approach

### WiFi Networks (PSK-based)
**SSID → Fixed VLAN → DHCP Pool Assignment**

Each SSID connects to a specific VLAN:
- `Blackfriars-Friars` → VLAN 10
- `Blackfriars-Staff` → VLAN 20
- `Blackfriars-Students` → VLAN 30
- `Blackfriars-Guests` → VLAN 40
- etc.

Within each VLAN, Kea DHCP assigns different IP pools based on MAC registration:
- **Registered**: .5 to .127, DNS: 8.8.8.8 (full internet), lease: 24 hours
- **Newly Unregistered**: .128 to .191, DNS: 192.168.x.4 (walled garden), lease: 60 seconds
- **Old Unregistered**: .192 to .254, DNS: 192.168.x.4 (walled garden), lease: 24 hours

**Newly Unregistered**: First seen <30 minutes ago
**Old Unregistered**: First seen ≥30 minutes ago (reduces DHCP traffic)

### Wired Connections (Ports 19, 21)
**Keep existing RADIUS MAC authentication with CoA**

Allows dynamic VLAN assignment based on user status (friars, staff, students, etc.)

## Registration Flow (WiFi)

1. User connects to SSID → Gets VLAN based on SSID
2. Device is "newly unregistered" (first seen <30 min)
3. Device gets short-lease IP (.128-.191, 60 second lease) with DNS pointing to portal
4. Browser redirects to captive portal
5. User enters email, first name, last name
6. Portal:
   - Registers MAC in database with timestamp
   - Moves MAC to "registered" client class in Kea
   - Sends email to admin (guest master)
   - Sends confirmation email to user with unregister link
   - Shows 30-second progress bar: "Activating your connection..."
7. Device DHCP lease expires (≤60 seconds)
8. Device renews lease → Gets registered IP (.5-.127) with public DNS
9. Progress bar detects internet access → "Connected!"
10. Full internet access granted

**Note**: After 30 minutes, unregistered MACs move to "old unregistered" pool (.192-.254, 24hr lease) to reduce DHCP traffic.

## Unregistration Flow

1. User clicks unregister link in email
2. Portal:
   - Verifies token
   - Removes MAC from database
   - Removes MAC from Kea host reservations
3. DHCP lease renewal triggered
4. Device gets unregistered IP again
5. Restricted access (walled garden)

## Database Schema Updates

### Devices Table
Add fields:
- `connection_type`: 'wifi' or 'wired'
- `ssid`: SSID for WiFi connections
- `unregister_token`: For email unregister link

### Settings Table
Add:
- `kea_control_socket`: Path to Kea control socket
- `kea_api_url`: Kea API endpoint (if using HTTP)

## Kea Configuration

### Split DHCP Pools per VLAN

Example for VLAN 40 (Guests):

```json
{
  "subnet": "192.168.40.0/24",
  "pools": [
    {
      "pool": "192.168.40.5 - 192.168.40.191",
      "client-class": "registered-40"
    },
    {
      "pool": "192.168.40.192 - 192.168.40.254",
      "client-class": "unregistered-40"
    }
  ],
  "option-data": [
    { "name": "routers", "data": "192.168.40.1" }
  ],
  "reservations": []
}
```

### Client Classification Hook

Kea hook that:
1. Checks if MAC is in registered database
2. Assigns appropriate client class
3. Returns correct pool and DNS settings

### Host Reservation Management

Portal uses Kea API to:
- Add host reservation when device registered
- Remove host reservation when device unregistered
- Trigger lease refresh

## Implementation Components

### 1. Kea Integration Module
**File**: `captive-portal/app/kea_integration.py`

Functions:
- `register_mac_in_kea(mac, vlan, ip_pool='registered')`
- `unregister_mac_from_kea(mac, vlan)`
- `trigger_dhcp_renewal(mac, ip)`
- `get_mac_status(mac)`

### 2. Updated Registration Logic
**File**: `captive-portal/app/app.py`

Detect connection type:
- Check if request came via wired port (look at source VLAN + port mapping)
- Or WiFi (all other cases)

WiFi registration:
- No RADIUS CoA
- Kea host reservation instead
- Different email templates

Wired registration:
- Keep existing RADIUS CoA logic
- Full status-based VLAN assignment

### 3. Email Templates
**New templates:**
- Registration confirmation with unregister link
- Guest master notification

### 4. Unregister Endpoint
**Route**: `/unregister/<token>`

Validates token and removes device registration.

## DNS Configuration for Walled Garden

Unregistered devices get DNS: 192.168.x.4 (the Pi)

Configure dnsmasq on Pi to:
- Redirect all DNS queries to portal IP
- Allow access to portal only
- Block all other traffic (firewall rules)

## Firewall Rules (on Pi or Switch)

### For Unregistered IPs (.192-.254):
```bash
# Allow access to portal only
iptables -A FORWARD -s 192.168.40.192/26 -d 192.168.40.4 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s 192.168.40.192/26 -d 192.168.40.4 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -s 192.168.40.192/26 -d 192.168.40.4 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -s 192.168.40.192/26 -j DROP
```

### For Registered IPs (.5-.191):
```bash
# Allow all internet access
iptables -A FORWARD -s 192.168.40.5/25 -j ACCEPT
```

## Advantages

✅ **User-friendly**: Simple WiFi password, no certificates
✅ **Flexible**: Different SSIDs for different purposes
✅ **Secure**: MAC registration prevents unauthorized access
✅ **Self-service**: Users can unregister via email link
✅ **Audit trail**: All registrations logged
✅ **Hybrid**: Wired connections still use RADIUS for flexibility

## Migration Path

1. **Phase 1**: Implement Kea integration module
2. **Phase 2**: Update portal registration logic
3. **Phase 3**: Configure Kea with split pools
4. **Phase 4**: Update email templates
5. **Phase 5**: Add unregister functionality
6. **Phase 6**: Configure firewall rules
7. **Phase 7**: Test with one SSID/VLAN
8. **Phase 8**: Roll out to all SSIDs

## Testing Checklist

- [ ] WiFi device connects to SSID, gets unregistered IP
- [ ] Portal accessible from unregistered IP
- [ ] Internet blocked for unregistered IP
- [ ] Registration completes successfully
- [ ] DHCP lease renewed after registration
- [ ] Device gets registered IP
- [ ] Internet access works
- [ ] Admin email received
- [ ] User confirmation email received
- [ ] Unregister link works
- [ ] Device returns to unregistered pool
- [ ] Wired connections still work with RADIUS
- [ ] RADIUS CoA still works for wired ports
