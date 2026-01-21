# Quick Reference: Block/Unblock Workflow

## Admin Blocks a Device

**What happens immediately:**
1. ✓ Database: `registration_status` → 'blocked'
2. ✓ HP5130: ACL deny rule added for current IP (e.g., rule 101: deny 192.168.10.150)
3. ✓ Kea: Device assigned to BLOCKED client class
4. ✓ Result: Device loses internet access **instantly**

**What happens after lease expires (≤4 hours):**
1. ✓ Kea hook: ACL rule for old IP removed automatically
2. ✓ Old IP freed for reuse
3. ✓ Device gets new IP from BLOCKED pool (.224-.254)
4. ✓ Captive portal shows "You have been blocked" message

## Admin Unblocks a Device

**What happens immediately:**
1. ✓ Database: `registration_status` → 'active'
2. ✓ HP5130: ACL deny rule removed (if exists)
3. ✓ Kea: Device removed from BLOCKED class
4. ✓ Result: Device can access internet again

**What happens after lease renewal:**
1. ✓ Device gets IP from unregistered pool (.128-.223)
2. ✓ Can register via captive portal normally

## IP Pools by Range

| Pool | IP Range | Purpose | Access |
|------|----------|---------|--------|
| REGISTERED | .5-.127 | Approved devices | Full internet |
| NEWLY_UNREGISTERED | .128-.191 | New devices (≤30min) | Walled garden |
| OLD_UNREGISTERED | .192-.223 | Long-term unregistered | Walled garden |
| BLOCKED | .224-.254 | Blocked devices | Walled garden + block message |

## ACL Rules by Range

| Rules | Purpose |
|-------|---------|
| 10-99 | Normal walled garden rules |
| 101-199 | **Blocked individual IPs** (managed by portal) |
| 200+ | Default permit |

## Key Commands

### Check ACL for blocked IPs
```bash
display acl 3100  # VLAN 10
```

### Manual block/unblock
```bash
python3 /app/switch_acl_manager.py block 192.168.10.150 10
python3 /app/switch_acl_manager.py unblock 192.168.10.150 10
```

### View ACL cleanup log
```bash
tail -f /var/log/kea-acl-cleanup.log
```

### Test connectivity from switch
```bash
ping 192.168.99.1  # From admin PC
ssh admin@192.168.99.1
```

## Environment Variables Needed

```bash
SWITCH_HOST=192.168.99.1
SWITCH_USER=admin
SWITCH_PASS=your_password
SWITCH_SSH_PORT=22
```
