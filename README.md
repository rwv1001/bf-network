# Blackfriars Network - Captive Portal System

## Current Implementation: DNS Hijacking (November 2025)

This system uses **DNS hijacking** for WiFi registration and **RADIUS CoA** for wired registration.

## Quick Overview

### WiFi Registration (DNS Hijacking)
```
Unregistered Device → Gets IP from single pool
  → Kea hook hijacks DNS (all domains → captive portal)
  → User registers
  → Portal removes hijack
  → Instant internet access
```

### Wired Registration (RADIUS CoA)
```
Unregistered Device → RADIUS assigns VLAN 99
  → User registers  
  → Portal sends CoA
  → Switch moves to correct VLAN
  → Full access
```

## Key Features

✅ **Instant activation** - WiFi devices get internet immediately after registration (no DHCP renewal)
✅ **Simple configuration** - Single IP pool per VLAN, no client classes or subnet switching
✅ **Automatic enforcement** - Kea hook handles hijacking, portal handles unhijacking
✅ **Works everywhere** - DNS hijacking effective for all devices and websites
✅ **Persistent across reboots** - IP alias and iptables rules survive restarts

## Documentation

### Current System (DNS Hijacking)
- **[DNS_HIJACK_IMPLEMENTATION.md](DNS_HIJACK_IMPLEMENTATION.md)** - Complete implementation guide ⭐
- **[SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md)** - Architecture overview
- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Deployment procedures
- **[SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)** - Security configuration
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Common commands

### Component-Specific Docs
- **[captive-portal/README.md](captive-portal/README.md)** - Portal application details
- **[freeradius/COA_SETUP.md](freeradius/COA_SETUP.md)** - RADIUS CoA configuration
- **[HP5130_WALLED_GARDEN.md](HP5130_WALLED_GARDEN.md)** - Switch ACL configuration

### Archived Documentation
Old implementations (multi-pool DHCP, client classes, subnet switching) are in `docs/archived/`.

## Architecture Components

### 1. Dual DNSmasq (`dnsmasq/`)
- **Normal DNS** (192.168.99.4): Resolves domains normally
- **Hijacking DNS** (192.168.99.5): Returns portal IP for ALL domains

### 2. Kea DHCP with Custom Hook (`kea/`)
- Single pool per VLAN (.6-.254)
- Custom hook: `dhcp_dns_hijack.so`
- Automatically hijacks/unhijacks DNS based on reservations

### 3. Captive Portal (`captive-portal/`)
- Flask web application
- PostgreSQL database
- Email notifications
- DNS hijacking integration

### 4. RADIUS Server (`freeradius/`)
- MAC authentication for wired ports
- CoA (Change-of-Authorization) for VLAN changes

### 5. DNS Hijacking Scripts (`scripts/`)
- `dns-hijack.sh` - Manage iptables rules
- `setup-ip-alias.sh` - Create 192.168.99.5 IP

## VLAN Structure

| User Type | VLAN | Subnet | Registration |
|-----------|------|--------|--------------|
| Friars | 10 | 192.168.10.0/24 | Pre-authorized |
| Staff | 20 | 192.168.20.0/24 | Pre-authorized |
| Students | 30 | 192.168.30.0/24 | Auto-approve |
| Guests | 40 | 192.168.40.0/24 | Auto-approve |
| Contractors | 50 | 192.168.50.0/24 | Admin approval |
| Volunteers | 60 | 192.168.60.0/24 | Auto-approve |
| IoT | 70 | 192.168.70.0/24 | Manual config |
| Restricted | 90 | 192.168.90.0/24 | Blocked users |
| Unregistered | 99 | 192.168.99.0/24 | Wired onboarding |

## Quick Commands

### Check DNS
```bash
# Normal DNS - should resolve correctly
dig @192.168.99.4 google.com +short

# Hijacked DNS - should return portal IP
dig @192.168.99.5 google.com +short
```

### Manage DNS Hijacking
```bash
# Hijack specific IP
sudo /home/admin/bf-network/scripts/dns-hijack.sh hijack 192.168.10.100

# Unhijack specific IP
sudo /home/admin/bf-network/scripts/dns-hijack.sh unhijack 192.168.10.100

# View all hijacked IPs
sudo iptables -t nat -L PREROUTING -n -v | grep 192.168.99.5
```

### Service Status
```bash
# Check all services
docker ps --format "table {{.Names}}\t{{.Status}}"

# Check Kea logs
docker logs kea --tail 50 | grep "DNS Hijack"

# Check DNSmasq
docker logs dnsmasq-normal --tail 20
docker logs dnsmasq-hijack --tail 20

# Check captive portal
docker logs captive-portal-web --tail 50
```

### Restart Services
```bash
# Restart Kea
docker restart kea

# Restart DNSmasq
cd /home/admin/bf-network/dnsmasq && docker compose restart

# Restart portal
cd /home/admin/bf-network/captive-portal && docker compose restart web
```

## Testing

### Test Unregistered Device
1. Connect device to WiFi
2. Device gets IP from .6-.254 range
3. Try visiting any website → redirects to captive portal
4. Register via portal
5. Internet works immediately (no reconnection needed)

### Test Wired Device
1. Connect to wired port (e.g., port 19, 21)
2. Device gets IP on VLAN 99
3. Register via portal
4. Device moves to correct VLAN (CoA)
5. Full access granted

## Troubleshooting

### DNS not hijacking
```bash
# Check IP alias exists
ip addr show eth0.99 | grep 192.168.99.5

# Check DNSmasq hijack running
docker ps | grep dnsmasq-hijack

# Test hijack DNS directly
dig @192.168.99.5 example.com +short
```

### Device not getting internet after registration
```bash
# Check if unhijack was called
docker logs captive-portal-web | grep unhijack

# Check iptables rules
sudo iptables -t nat -L PREROUTING -n -v

# Manually unhijack
sudo /home/admin/bf-network/scripts/dns-hijack.sh unhijack <device_ip>
```

### Kea hook not working
```bash
# Check hook loaded
docker logs kea | grep "DNS Hijack Hook: Loaded"

# Check hook detecting devices
docker logs kea | grep "DNS Hijack Hook:"

# Verify hook file exists
docker exec kea ls -lh /usr/local/lib/kea/hooks/dhcp_dns_hijack.so
```

## Getting Help

1. Check **[DNS_HIJACK_IMPLEMENTATION.md](DNS_HIJACK_IMPLEMENTATION.md)** for detailed troubleshooting
2. Review logs: `docker logs <container_name>`
3. Check iptables: `sudo iptables -t nat -L PREROUTING -n -v`
4. Verify DNS: `dig @192.168.99.4` and `dig @192.168.99.5`

## Project History

- **November 2025**: Switched to DNS hijacking approach (current)
- **November 2025**: Attempted multi-pool DHCP with NAK packets (deprecated)
- **November 2025**: Client classes approach (deprecated)
- **November 2025**: Initial captive portal with wired CoA (still used for wired)

See `docs/archived/` for old implementation documentation.
