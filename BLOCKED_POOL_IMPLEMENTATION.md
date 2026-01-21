# IP-Based Blocking with ACL and Pool Management

## Overview

This implementation allows administrators to block devices immediately via switch ACLs while managing blocked devices through Kea DHCP pools. The solution addresses IP reuse concerns through automatic ACL cleanup when leases expire.

## Architecture

### IP Pool Structure (per VLAN)

- **Registered**: `.5-.127` (123 IPs) - Full internet access
- **Newly Unregistered**: `.128-.191` (64 IPs) - Walled garden, short lease (60s)
- **Old Unregistered**: `.192-.223` (32 IPs) - Walled garden, long lease (4h)
- **Blocked**: `.224-.254` (31 IPs) - Walled garden + "blocked" message

### How Blocking Works

1. **Admin clicks "Block"** in portal dashboard
   - Device status → 'blocked' in database
   - **Immediate ACL deny rule** added to HP5130 for current IP (blocks internet instantly, bypasses DoH)
   - **Kea reservation** created assigning device to BLOCKED client class

2. **Device continues using current IP** (still blocked by ACL rule)
   - Internet access denied immediately
   - Can only reach captive portal (walled garden)

3. **Lease expires** (within 4 hours max)
   - Kea hook script (`acl-cleanup-hook.sh`) automatically **removes ACL rule** for old IP
   - Old IP is freed for reuse by other devices
   - Device gets new IP from BLOCKED pool (.224-.254)

4. **Device on new IP from BLOCKED pool**
   - No ACL rule needed (blocked pool has walled garden ACL applied to entire range)
   - Captive portal detects IP is in blocked range → shows "blocked" message
   - Device stays in blocked pool until admin unblocks

### How Unblocking Works

1. **Admin clicks "Unblock"**
   - Device status → 'active' in database
   - **ACL deny rule removed** (if it exists) from HP5130
   - **Kea reservation removed** from BLOCKED class
   
2. **Next DHCP renewal**
   - Device gets IP from unregistered pool (.128-.223)
   - Can register normally via captive portal

## Component Files

### 1. Switch ACL Manager (`captive-portal/app/switch_acl_manager.py`)
- **SSH-based** communication with HP5130 (using netmiko)
- Manages ACL rules 101-199 for blocking individual IPs
- Auto-finds next available rule number
- Properly cleans up rules when unblocking

### 2. Kea Hook Script (`kea/scripts/acl-cleanup-hook.sh`)
- Called by Kea on lease events (expire, release, renew)
- Removes ACL rules when blocked device's lease expires
- Frees IP addresses for reuse
- Logs all actions to `/var/log/kea-acl-cleanup.log`

### 3. Kea Configuration (`kea/config/dhcp4-four-pool-blocked.json`)
- Defines four client classes: REGISTERED, BLOCKED, NEWLY_UNREGISTERED, OLD_UNREGISTERED
- Each VLAN has four pools matching the IP ranges above
- Shorter leases (1h) for BLOCKED pool to speed up pool transitions
- Hook script integration for automatic ACL cleanup

### 4. HP5130 ACL Update Script (`update-hp5130-blocked-pool.py`)
- One-time script to update existing ACLs for BLOCKED pool support
- Adds rules 65-73 for blocked pool (.224-.254) traffic
- Same walled garden permissions as unregistered pools

### 5. Updated Portal App (`captive-portal/app/app.py`)
- `assign_device_to_blocked_pool()` - Creates Kea reservation with BLOCKED class
- `remove_device_from_blocked_pool()` - Removes Kea reservation
- Updated `admin_block_device()` - Applies both ACL + pool assignment
- Updated `admin_unblock_device()` - Removes both ACL + pool assignment

## Setup Instructions

### Step 1: Update HP5130 ACLs

Add rules for blocked pool (.224-.254):

```bash
cd /home/admin/bf-network
python3 update-hp5130-blocked-pool.py --dry-run  # Preview changes
python3 update-hp5130-blocked-pool.py            # Apply changes
```

### Step 2: Update Kea Configuration

Copy the four-pool configuration:

```bash
cd /home/admin/bf-network/kea
cp config/dhcp4-four-pool-blocked.json kea-dhcp4.conf
```

Make hook script executable:

```bash
chmod +x scripts/acl-cleanup-hook.sh
```

### Step 3: Configure Switch Credentials

Add to `.env` file or docker-compose environment:

```bash
SWITCH_HOST=192.168.99.1
SWITCH_USER=admin
SWITCH_PASS=your_switch_password_here
SWITCH_SSH_PORT=22
```

### Step 4: Rebuild and Restart Portal

```bash
cd /home/admin/bf-network/captive-portal
docker-compose down
docker-compose build
docker-compose up -d
```

### Step 5: Restart Kea

```bash
cd /home/admin/bf-network/kea
docker-compose restart
```

## Testing

### Test Blocking

1. Find a test device in admin dashboard
2. Click "Block" button
3. Verify:
   - Flash message confirms ACL + pool assignment
   - Device loses internet immediately (ACL working)
   - `display acl 3100` on switch shows new rule 101+ for device's IP

4. Wait for lease to expire (or force renewal on device)
5. Verify:
   - Device gets new IP in .224-.254 range
   - Old ACL rule removed automatically
   - Captive portal shows "blocked" message

### Test Unblocking

1. Click "Unblock" on blocked device
2. Verify:
   - Flash message confirms ACL removal + pool removal
   - ACL rule removed from switch
   - Device can access internet again (if still on old IP)

3. Wait for lease renewal
4. Verify:
   - Device gets IP in unregistered pool (.128-.223)
   - Can access captive portal for registration

## Monitoring

### View ACL Rules on Switch

```
display acl 3100  # VLAN 10
display acl 3200  # VLAN 20
# etc.
```

### Check Kea Logs

```bash
docker logs kea-dhcp4
```

### Check ACL Cleanup Log

```bash
tail -f /var/log/kea-acl-cleanup.log
```

### View Blocked IPs via Script

```bash
python3 captive-portal/app/switch_acl_manager.py list 10  # Lists blocked IPs for VLAN 10
```

## ACL Rule Management

- **Rules 101-199**: Reserved for blocked individual IPs
- **Automatic allocation**: Script finds next available number
- **Limit**: 99 simultaneous IP blocks per VLAN
- **Automatic cleanup**: Removed when lease expires via Kea hook

## Troubleshooting

### ACL Block Not Working

```bash
# Check if rule was added
display acl 3100

# Check switch credentials
env | grep SWITCH

# Test manually
python3 captive-portal/app/switch_acl_manager.py block 192.168.10.150 10
```

### Pool Assignment Not Working

```bash
# Check Kea logs
docker logs kea-dhcp4

# Verify hook script is executable
ls -la /home/admin/bf-network/kea/scripts/acl-cleanup-hook.sh
```

### ACL Cleanup Not Triggering

```bash
# Check if hook script is configured in kea-dhcp4.conf
grep acl-cleanup-hook kea/kea-dhcp4.conf

# Check cleanup log
tail -f /var/log/kea-acl-cleanup.log

# Test manually
bash kea/scripts/acl-cleanup-hook.sh
```

## Advantages of This Approach

1. **Immediate blocking** - ACL denies traffic instantly, bypasses DNS-over-HTTPS
2. **IP reuse** - Automatic ACL cleanup frees IPs when leases expire
3. **Persistent blocking** - BLOCKED pool keeps device blocked after IP change
4. **Simple management** - Admin just clicks block/unblock, system handles the rest
5. **Scalable** - 99 simultaneous blocks per VLAN, 31 IPs in blocked pool
6. **Reliable** - SSH-based (no NETCONF issues), proven netmiko library

## Future Enhancements

- [ ] Web UI to view current ACL rules
- [ ] Automatic unblock after time period
- [ ] Email notifications when devices are blocked/unblocked
- [ ] Statistics on blocked devices over time
