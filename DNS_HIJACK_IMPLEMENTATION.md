# DNS Hijacking Captive Portal Implementation

## Overview

This system uses **DNS hijacking** to redirect unregistered devices to the captive portal instead of managing multiple DHCP pools. This is simpler, more flexible, and works across all VLANs.

## Architecture

```
Unregistered Device
  ↓
DHCP: Gets IP from single pool (.6-.254), DNS=192.168.99.4
  ↓
Kea Hook: Detects no reservation → runs dns-hijack.sh hijack <ip>
  ↓
iptables: Redirects DNS queries from <ip> to 192.168.99.5
  ↓
DNSmasq (192.168.99.5): Returns 192.168.99.4 for ALL domains
  ↓
Device sees captive portal for every website
  ↓
User registers via portal
  ↓
Portal calls: dns-hijack.sh unhijack <ip>
  ↓
iptables: Removes redirect rule
  ↓
Device now uses normal DNS (192.168.99.4) → full internet access
```

## Components

### 1. Two DNSmasq Instances
- **Normal DNS** (`192.168.99.4`): Resolves domains normally for registered devices
- **Hijacking DNS** (`192.168.99.5`): Returns `192.168.99.4` for ALL domains, forcing unregistered devices to captive portal

### 2. IP Alias
- `192.168.99.5/32` added to `eth0.99` via systemd service
- Persists across reboots via `/etc/systemd/system/ip-alias-dns-hijack.service`

### 3. Kea DHCP Configuration
- **Single pool per VLAN**: `192.168.n.6 - 192.168.n.254`
- **All devices** get DNS server `192.168.99.4`
- No more split pools or client classes
- Simple and maintainable

### 4. Kea Hook (`dhcp_dns_hijack.so`)
- Runs on `lease4_select` when device gets IP
- Checks PostgreSQL for reservations
- **No reservation**: Calls `dns-hijack.sh hijack <ip>`
- **Has reservation**: Calls `dns-hijack.sh unhijack <ip>`

### 5. DNS Hijacking Script
```bash
/home/admin/bf-network/scripts/dns-hijack.sh {hijack|unhijack} <ip_address>
```
- **hijack**: Adds iptables DNAT rule to redirect DNS queries to 192.168.99.5
- **unhijack**: Removes iptables DNAT rule

### 6. Captive Portal Integration
- On successful registration, calls `manage_dns_hijack('unhijack', ip_address)`
- Removes DNS redirect immediately
- Device can access normal internet without renewal delay

## Files Modified

### Configuration Files
- `/home/admin/bf-network/kea/config/dhcp4.json` - Simplified to single pools
- `/home/admin/bf-network/dnsmasq/conf/blac-onboarding.conf` - Listen on 192.168.99.4 only
- `/home/admin/bf-network/dnsmasq/conf/hijack.conf` - NEW: Hijacking DNS config
- `/home/admin/bf-network/dnsmasq/docker-compose.yml` - Two DNSmasq instances

### Scripts
- `/home/admin/bf-network/scripts/setup-ip-alias.sh` - Add 192.168.99.5 IP alias
- `/home/admin/bf-network/scripts/dns-hijack.sh` - Manage iptables DNS redirect rules

### Code
- `/home/admin/bf-network/kea-hooks/dynamic_subnet/dns_hijack_hook.cc` - NEW: Simplified hook
- `/home/admin/bf-network/captive-portal/app/app.py` - Added `manage_dns_hijack()` function

## Testing

### Test DNS Resolution
```bash
# Normal DNS - should resolve to real IP
dig @192.168.99.4 google.com +short

# Hijacked DNS - should resolve to 192.168.99.4 (captive portal)
dig @192.168.99.5 google.com +short
```

### Test DNS Hijacking
```bash
# Hijack a test IP
sudo /home/admin/bf-network/scripts/dns-hijack.sh hijack 192.168.10.100

# Check iptables rules
sudo iptables -t nat -L PREROUTING -n -v | grep 192.168.10.100

# Unhijack
sudo /home/admin/bf-network/scripts/dns-hijack.sh unhijack 192.168.10.100
```

### Test Full Flow
1. Connect unregistered device to WiFi
2. Device gets IP from pool (.6-.254)
3. Device gets DNS=192.168.99.4
4. Kea hook detects no reservation → hijacks DNS
5. Device tries to visit any website → redirected to captive portal
6. User registers
7. Portal calls unhijack script
8. Device has normal internet access

## Advantages Over Pool-Based Approach

### Simpler Configuration
- One pool per VLAN instead of two
- No need for overlapping subnets or NAK packets
- Easier to understand and maintain

### Immediate Effect
- DNS hijacking takes effect instantly
- No waiting for DHCP renewal
- No NAK/DISCOVER/REQUEST cycle needed

### More Flexible
- Works across all VLANs consistently
- Easy to add new VLANs (just one pool)
- Can hijack/unhijack individual devices on demand

### Better UX
- Faster transitions from unregistered → registered
- No IP address changes
- Device keeps same IP through registration

## Troubleshooting

### Check DNSmasq Status
```bash
docker ps | grep dnsmasq
docker logs dnsmasq-normal
docker logs dnsmasq-hijack
```

### Check DNS Resolution
```bash
# Should resolve normally
dig @192.168.99.4 example.com

# Should resolve to 192.168.99.4
dig @192.168.99.5 example.com
```

### Check iptables Rules
```bash
sudo iptables -t nat -L PREROUTING -n -v
```

### Check Kea Hook
```bash
docker logs kea | grep "DNS Hijack Hook"
```

### View Active Hijacked IPs
```bash
sudo iptables -t nat -L PREROUTING -n -v | grep "192.168.99.5:53"
```

## Maintenance

### Add New VLAN
1. Add subnet to `/home/admin/bf-network/kea/config/dhcp4.json`:
```json
{
  "subnet": "192.168.XX.0/24",
  "id": XX,
  "pools": [
    {
      "pool": "192.168.XX.6 - 192.168.XX.254"
    }
  ],
  "interface": "eth0.XX",
  "option-data": [
    {
      "name": "routers",
      "data": "192.168.XX.1"
    }
  ],
  "reservations": []
}
```
2. Restart Kea: `docker restart kea`

### Clear All DNS Hijacking Rules
```bash
# Remove all DNS hijack rules
sudo iptables -t nat -F PREROUTING
```

### Persist iptables Rules (if needed)
```bash
# Save current rules
sudo iptables-save > /etc/iptables/rules.v4

# Restore on boot (Debian/Raspbian)
sudo apt install iptables-persistent
```

## Future Enhancements

1. **Web Interface**: View/manage hijacked IPs from admin dashboard
2. **Rate Limiting**: Prevent DNS query flooding
3. **Logging**: Track hijack/unhijack events for analytics
4. **Auto-Cleanup**: Remove stale iptables rules for offline devices
5. **VLAN Expansion**: Apply to VLANs 70, 90 when interfaces exist
