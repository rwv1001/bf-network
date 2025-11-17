# HP 5130 Walled Garden Configuration for Captive Portal

## Overview

This guide configures ACLs (Access Control Lists) on the HP 5130 switch to create a "walled garden" for unregistered WiFi devices. Unregistered devices can only access the captive portal, while registered devices have full internet access.

## IP Ranges Per VLAN

Based on your Kea DHCP configuration with client classes:

**VLAN 10 (192.168.10.0/24):**
- **Registered**: `.5 - .127` (full internet)
- **Unregistered**: `.128 - .254` (portal only)

**Apply same pattern to all VLANs:** 20, 30, 40, 50, 60, 70, 90

## Configuration for VLAN 10

### Step 1: Create ACL for Unregistered Devices

```
# Create ACL to allow only portal access for unregistered IPs (.128-.254)
acl advanced 3010 match-order auto
 description "VLAN10 Walled Garden - Unregistered Devices"
 
 # Allow DNS to portal (Pi)
 rule 10 permit udp source 192.168.10.128 0.0.0.127 destination 192.168.10.4 0 destination-port eq 53
 
 # Allow HTTP to portal
 rule 20 permit tcp source 192.168.10.128 0.0.0.127 destination 192.168.10.4 0 destination-port eq 80
 
 # Allow HTTPS to portal
 rule 30 permit tcp source 192.168.10.128 0.0.0.127 destination 192.168.10.4 0 destination-port eq 443
 
 # Allow DHCP
 rule 40 permit udp source 192.168.10.128 0.0.0.127 destination 255.255.255.255 0 destination-port eq 67
 
 # Allow NTP (optional - helps with HTTPS certificate validation)
 rule 50 permit udp source 192.168.10.128 0.0.0.127 destination any destination-port eq 123
 
 # Block everything else from unregistered range
 rule 100 deny ip source 192.168.10.128 0.0.0.127 destination any
```

### Step 2: Create ACL for Registered Devices

```
# Create ACL to allow full internet for registered IPs (.5-.127)
acl advanced 3011 match-order auto
 description "VLAN10 Full Access - Registered Devices"
 
 # Allow all traffic from registered range
 rule 10 permit ip source 192.168.10.5 0.0.0.122 destination any
```

### Step 3: Apply ACLs to VLAN 10 Interface

```
interface Vlan-interface10
 description GW_VLAN10
 ip address 192.168.10.1 255.255.255.0
 
 # Apply ACL for unregistered devices (outbound = leaving the VLAN)
 packet-filter 3010 outbound
 
 # Apply ACL for registered devices (outbound)
 packet-filter 3011 outbound
```

## Complete Configuration for All VLANs

Apply similar configuration for each VLAN. Here's the pattern:

### VLAN 20 (Staff)
```
acl advanced 3020 match-order auto
 description "VLAN20 Walled Garden - Unregistered"
 rule 10 permit udp source 192.168.20.128 0.0.0.127 destination 192.168.20.4 0 destination-port eq 53
 rule 20 permit tcp source 192.168.20.128 0.0.0.127 destination 192.168.20.4 0 destination-port eq 80
 rule 30 permit tcp source 192.168.20.128 0.0.0.127 destination 192.168.20.4 0 destination-port eq 443
 rule 40 permit udp source 192.168.20.128 0.0.0.127 destination 255.255.255.255 0 destination-port eq 67
 rule 50 permit udp source 192.168.20.128 0.0.0.127 destination any destination-port eq 123
 rule 100 deny ip source 192.168.20.128 0.0.0.127 destination any

acl advanced 3021 match-order auto
 description "VLAN20 Full Access - Registered"
 rule 10 permit ip source 192.168.20.5 0.0.0.122 destination any

interface Vlan-interface20
 packet-filter 3020 outbound
 packet-filter 3021 outbound
```

### VLAN 30 (Students)
```
acl advanced 3030 match-order auto
 description "VLAN30 Walled Garden - Unregistered"
 rule 10 permit udp source 192.168.30.128 0.0.0.127 destination 192.168.30.4 0 destination-port eq 53
 rule 20 permit tcp source 192.168.30.128 0.0.0.127 destination 192.168.30.4 0 destination-port eq 80
 rule 30 permit tcp source 192.168.30.128 0.0.0.127 destination 192.168.30.4 0 destination-port eq 443
 rule 40 permit udp source 192.168.30.128 0.0.0.127 destination 255.255.255.255 0 destination-port eq 67
 rule 50 permit udp source 192.168.30.128 0.0.0.127 destination any destination-port eq 123
 rule 100 deny ip source 192.168.30.128 0.0.0.127 destination any

acl advanced 3031 match-order auto
 description "VLAN30 Full Access - Registered"
 rule 10 permit ip source 192.168.30.5 0.0.0.122 destination any

interface Vlan-interface30
 packet-filter 3030 outbound
 packet-filter 3031 outbound
```

### VLAN 40 (Guests)
```
acl advanced 3040 match-order auto
 description "VLAN40 Walled Garden - Unregistered"
 rule 10 permit udp source 192.168.40.128 0.0.0.127 destination 192.168.40.4 0 destination-port eq 53
 rule 20 permit tcp source 192.168.40.128 0.0.0.127 destination 192.168.40.4 0 destination-port eq 80
 rule 30 permit tcp source 192.168.40.128 0.0.0.127 destination 192.168.40.4 0 destination-port eq 443
 rule 40 permit udp source 192.168.40.128 0.0.0.127 destination 255.255.255.255 0 destination-port eq 67
 rule 50 permit udp source 192.168.40.128 0.0.0.127 destination any destination-port eq 123
 rule 100 deny ip source 192.168.40.128 0.0.0.127 destination any

acl advanced 3041 match-order auto
 description "VLAN40 Full Access - Registered"
 rule 10 permit ip source 192.168.40.5 0.0.0.122 destination any

interface Vlan-interface40
 packet-filter 3040 outbound
 packet-filter 3041 outbound
```

## Important Notes

### Wildcard Mask Calculation

HP/Comware uses **wildcard masks** (inverse of subnet mask):
- **0.0.0.0** = exact match
- **0.0.0.127** = match 128 IPs (.128-.255)
- **0.0.0.122** = match 123 IPs (.5-.127)

**Example:**
- Source `192.168.10.128 0.0.0.127` matches 192.168.10.128 through 192.168.10.255
- Source `192.168.10.5 0.0.0.122` matches 192.168.10.5 through 192.168.10.127

### ACL Numbering Convention

I've used a pattern where:
- **30X0** = Unregistered ACL for VLAN X (e.g., 3010 for VLAN 10)
- **30X1** = Registered ACL for VLAN X (e.g., 3011 for VLAN 10)

### Portal IP Address

The portal is accessible on **192.168.X.4** on each VLAN (the Pi with host networking).

### DNS Redirection

For proper captive portal detection, unregistered devices should use DNS **192.168.X.4** (the Pi). This is already configured in your Kea DHCP client classes:

```json
"UNREGISTERED": {
  "option-data": [
    { "name": "domain-name-servers", "data": "192.168.99.4" }
  ]
}
```

**But wait!** For VLANs 10, 20, 30, 40, etc., you need to update Kea to use the correct DNS per VLAN:
- VLAN 10: DNS = 192.168.10.4
- VLAN 20: DNS = 192.168.20.4
- etc.

## Verification Commands

### Check ACL Configuration
```
display acl advanced 3010
display acl advanced 3011
```

### Check Applied ACLs
```
display packet-filter interface Vlan-interface10
```

### Monitor ACL Hits
```
display acl advanced 3010
# Look for "rule X ... (X times matched)"
```

### Test from Client

**From unregistered device (.128-.254):**
```bash
# Should work (portal)
curl http://192.168.10.4

# Should fail (internet)
ping 8.8.8.8
curl http://google.com
```

**From registered device (.5-.127):**
```bash
# Should work (internet)
ping 8.8.8.8
curl http://google.com
```

## Troubleshooting

### Portal not accessible from unregistered IP

**Check:**
1. ACL 3010 is applied: `display packet-filter interface Vlan-interface10`
2. Rule 20/30 permits traffic: `display acl advanced 3010`
3. Portal is actually listening on 192.168.10.4:80

**Fix:**
```
# Verify portal container
docker ps | grep captive-portal-web

# Test from switch itself
ping 192.168.10.4
```

### Internet not blocked for unregistered IPs

**Check:**
1. Deny rule exists: `display acl advanced 3010` (rule 100)
2. ACL is applied outbound: `display packet-filter interface Vlan-interface10`
3. No other permissive rules

**Fix:**
```
# Check ACL match order
display acl advanced 3010
# Should show "match-order: auto"
```

### Registered devices can't access internet

**Check:**
1. ACL 3011 exists: `display acl advanced 3011`
2. ACL 3011 is applied: `display packet-filter interface Vlan-interface10`
3. Source IP range is correct (.5-.127)

**Fix:**
```
# Verify wildcard mask
# Should be 0.0.0.122 not 0.0.0.127
```

### Devices getting wrong IP range

This is a Kea DHCP issue, not ACL:
```bash
# Check Kea logs
docker logs kea

# Verify client class assignment
docker exec kea cat /kea/leases/kea-leases4.csv
```

## Advanced: Per-VLAN Portal DNS

Since you're using host networking, the portal is accessible on ALL VLAN interfaces at 192.168.X.4. However, your Kea configuration currently sets DNS to `192.168.99.4` for all unregistered devices.

**You should update** `kea/config/dhcp4-client-classes.json` to use per-subnet DNS:

```json
{
  "subnet": "192.168.10.0/24",
  "client-classes": [
    {
      "name": "UNREGISTERED",
      "option-data": [
        { "name": "domain-name-servers", "data": "192.168.10.4" }
      ]
    }
  ]
}
```

This ensures unregistered devices on VLAN 10 use 192.168.10.4 as DNS, which matches your ACL rules.

## Summary

With this configuration:
- ✅ Unregistered devices (.128-.254) can only access portal at 192.168.X.4
- ✅ Registered devices (.5-.127) have full internet access
- ✅ DHCP still works for all devices
- ✅ NTP allowed for certificate validation
- ✅ Each VLAN independently controlled

Apply this configuration to all your WiFi VLANs (10, 20, 30, 40, 50, 60, 70, 90) for a complete walled garden setup!
