# Restart Guide - Two-Pool Blocked Implementation

## What Changed

✅ **Kea DHCP configuration** - Now uses [dhcp4-two-pool-blocked.json](kea/config/dhcp4-two-pool-blocked.json)
✅ **Portal app** - Added IP range detection for blocked devices (.216-.254)
✅ **Kea hook script** - Mounted correctly to auto-remove ACL rules on lease expiry

## What Needs Restart

### 1. Kea DHCP (Required ✓)
Kea needs to restart to load the new two-pool configuration.

```bash
cd /home/admin/bf-network/kea
docker compose down
docker compose up -d
```

**Verify:**
```bash
docker logs kea | tail -20
# Should show: "Reading configuration from /kea/config/dhcp4-two-pool-blocked.json"
```

### 2. Captive Portal (Required ✓)
Portal needs rebuild to include updated app.py with blocked IP detection.

```bash
cd /home/admin/bf-network/captive-portal
docker compose down
docker compose build
docker compose up -d
```

**Verify:**
```bash
docker logs captive-portal-web-1 | grep -i "running\|starting"
```

### 3. DNSmasq (Not Required ✗)
No changes to DNS hijacking - already working correctly.

### 4. FreeRADIUS (Not Required ✗)
No changes to RADIUS CoA - already working correctly.

## Quick Restart All

```bash
# Set switch password in environment first
export SWITCH_PASS='your_switch_password'

# Restart Kea
cd /home/admin/bf-network/kea
docker compose down && docker compose up -d

# Restart Portal (rebuild to include code changes)
cd /home/admin/bf-network/captive-portal
docker compose down && docker compose build && docker compose up -d

# Check logs
docker logs kea | tail -20
docker logs captive-portal-web-1 | tail -20
```

## Test After Restart

1. **Check Kea pools:**
   ```bash
   docker exec kea cat /kea/leases/kea-leases4.csv | head -10
   ```

2. **Test blocked IP detection:**
   - Manually assign a device to blocked pool via admin panel
   - Wait for lease to expire or force release
   - Device should get IP in .216-.254 range
   - Visiting portal should show "blocked" message

3. **Check ACL cleanup hook:**
   ```bash
   docker exec kea ls -la /kea/scripts/
   docker exec kea cat /kea/scripts/acl-cleanup-hook.sh | head -20
   ```

## Expected Behavior After Restart

✅ **New devices** → Get IP from .5-.215 (unblocked pool)
✅ **Blocked devices** → Get IP from .216-.254 (blocked pool) after lease expires
✅ **Portal detection** → Shows "blocked" message for IPs in .216-.254
✅ **ACL cleanup** → Removes ACL rules automatically when lease expires
✅ **DNS hijacking** → Still controls walled garden (instant registration)

## Rollback (If Needed)

If something goes wrong, revert to previous Kea config:

```bash
cd /home/admin/bf-network/kea
# Edit docker-compose.yml to use previous config file
docker compose down
docker compose up -d
```

## Notes

- **No downtime for existing leases** - devices keep current IPs until renewal
- **ACL rules** - existing ACL rules (101-199) remain until cleanup hook runs
- **Switch config** - no changes needed to HP5130
- **DNS hijacking** - continues to work without interruption
