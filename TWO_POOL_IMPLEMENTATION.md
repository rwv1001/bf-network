# Two-Pool Blocked Implementation

## Summary

This is the **simplified** blocked device implementation using DNS hijacking for walled garden and a small blocked pool for persistent blocking.

## IP Pools (All VLANs)

| Pool | Range | IPs | Purpose |
|------|-------|-----|---------|
| **Unblocked** | `.5-.215` | 211 | All normal devices (both registered and unregistered) |
| **Blocked** | `.216-.254` | 39 | Blocked devices only |

## Access Control

**DNS Hijacking Controls Walled Garden:**
- DNS hijacked (.99.4 → .99.5) = Walled garden (captive portal)
- DNS not hijacked = Full internet access
- Portal detects IP range to show appropriate message

**Switch ACLs Only for Immediate Blocking:**
- ACL rules 101-199: Temporary individual IP blocks
- Applied immediately when admin clicks "block"
- Auto-removed when lease expires (via Kea hook)
- No range-based walled garden ACLs needed

## Workflows

### Registration (Instant!)
1. Device connects → Gets IP from unblocked pool (e.g., `.150`)
2. DNS hijacked → Sees captive portal ✓
3. User registers → **DNS hijack removed IMMEDIATELY** → Full internet ✓
4. **No DHCP wait!** Same IP, instant access
5. Background: Kea reservation created for future

### Blocking
1. **Admin clicks "Block":**
   - ACL deny rule added for current IP → **Immediate block** (bypasses DoH)
   - Kea: Device assigned to BLOCKED client class
   - DNS hijacked (if not already)

2. **Lease expires (≤4 hours):**
   - Kea hook: ACL rule auto-removed (frees IP for reuse)
   - Device gets new IP from blocked pool (.216-.254)
   - DNS stays hijacked
   - Portal detects blocked IP range → Shows "You are blocked"

### Unblocking
1. **Admin clicks "Unblock":**
   - ACL rule removed (if exists)
   - Kea: Device removed from BLOCKED class
   - DNS hijack remains (shows registration portal)

2. **Next DHCP renewal:**
   - Device gets IP from unblocked pool
   - Can register normally

## Key Files

**Created:**
- ✅ [kea/config/dhcp4-two-pool-blocked.json](kea/config/dhcp4-two-pool-blocked.json) - Two-pool Kea config
- ✅ [captive-portal/app/switch_acl_manager.py](captive-portal/app/switch_acl_manager.py) - SSH-based ACL management
- ✅ [kea/scripts/acl-cleanup-hook.sh](kea/scripts/acl-cleanup-hook.sh) - Auto-remove ACL rules on lease expiry

**Updated:**
- ✅ [captive-portal/app/app.py](captive-portal/app/app.py) - Added Kea pool assignment functions
- ✅ [captive-portal/docker-compose.yml](captive-portal/docker-compose.yml) - Added SWITCH_* env vars
- ✅ [captive-portal/app/requirements.txt](captive-portal/app/requirements.txt) - Added netmiko

**Not Needed:**
- ❌ Range-based walled garden ACLs on switch (DNS hijacking handles this)
- ❌ Complex multi-pool configs
- ❌ update-hp5130-blocked-pool.py (not needed)

## Portal Logic

The captive portal app needs to detect blocked IPs and show appropriate message:

```python
def is_blocked_ip(ip_address):
    """Check if IP is in blocked range (.216-.254)"""
    try:
        last_octet = int(ip_address.split('.')[-1])
        return 216 <= last_octet <= 254
    except:
        return False

@app.route('/register')
def register():
    ip = get_client_ip()
    mac = get_client_mac()
    
    # Check database first
    device = Device.query.filter_by(mac_address=mac).first()
    if device and device.registration_status == 'blocked':
        return render_template('blocked.html')
    
    # Also check IP range (in case device not in DB yet)
    if is_blocked_ip(ip):
        return render_template('blocked.html')
    
    # Normal registration flow
    return render_template('register.html')
```

## Setup Steps

1. **Copy Kea configuration:**
   ```bash
   cd /home/admin/bf-network/kea
   cp config/dhcp4-two-pool-blocked.json kea-dhcp4.conf
   ```

2. **Make hook script executable:**
   ```bash
   chmod +x scripts/acl-cleanup-hook.sh
   ```

3. **Set environment variables:**
   Add to `.env` or docker-compose:
   ```bash
   SWITCH_HOST=192.168.99.1
   SWITCH_USER=admin
   SWITCH_PASS=your_switch_password
   SWITCH_SSH_PORT=22
   ```

4. **Rebuild and restart:**
   ```bash
   cd captive-portal
   docker compose down
   docker compose build
   docker compose up -d
   
   cd ../kea
   docker compose restart
   ```

## Advantages

✅ **Simple** - Only 2 pools, easy to understand
✅ **Instant registration** - DNS hijack removed immediately, no DHCP wait
✅ **IP reuse** - ACL cleanup frees blocked IPs automatically
✅ **DoH-proof** - ACL blocks work even with DNS-over-HTTPS
✅ **Scalable** - 39 blocked IPs unlikely to run out
✅ **Clean** - No complex range-based ACLs on switch

## Monitoring

```bash
# Check ACL rules on switch
display acl 3100  # VLAN 10
display acl 3200  # VLAN 20

# Check Kea logs
docker logs kea-dhcp4

# Check ACL cleanup log
tail -f /var/log/kea-acl-cleanup.log

# List active leases
docker exec kea-dhcp4 cat /kea/leases/kea-leases4.csv | grep 192.168.10
```
