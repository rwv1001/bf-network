# Admin Dashboard Implementation

## Overview
Enhanced the captive portal admin dashboard with comprehensive device management capabilities and differentiated approval workflows.

## Features Implemented

### 1. Auto-Approval VLANs
Devices connecting from certain VLANs are automatically approved and registered without requiring administrator intervention.

**Auto-Approve VLANs:**
- VLAN 40 - Guests
- VLAN 30 - Students  
- VLAN 60 - Volunteers

**Admin-Approval VLANs:**
- VLAN 10 - Friars
- VLAN 20 - Staff
- VLAN 50 - Contractors

### 2. Enhanced Device Management Table
The admin dashboard now displays a comprehensive table of all registered devices with the following information:

**Columns:**
- **MAC Address** - Device hardware address (monospace font for easy reading)
- **Name** - User's first and last name (or "Unknown" if no associated user)
- **Email** - User's email address
- **Status** - Visual badge showing device status:
  - 🟢 **Active** (green) - Device has network access
  - 🔴 **Blocked** (red) - Device blocked from network, moved to restricted VLAN
  - 🟠 **Pending** (orange) - Awaiting approval
- **Type** - Connection type:
  - 📶 WiFi
  - 🔌 Wired
- **SSID** - WiFi network name (for WiFi devices)
- **First Seen** - Timestamp when device first connected
- **Last Seen** - Timestamp of last activity
- **VLAN** - Current VLAN assignment
- **Actions** - Management buttons:
  - 🚫 **Block** - Move device to restricted VLAN (VLAN 90)
  - ✅ **Unblock** - Restore device to appropriate VLAN based on user status
  - 🗑️ **Delete** - Remove device from database and disconnect from network

### 3. Admin Device Management Endpoints

#### Block Device (`/admin/device/<id>/block`)
- Sets device `registration_status` to 'blocked'
- For WiFi devices: Unregisters MAC from Kea DHCP (moves to unregistered pool)
- For wired devices: Sends RADIUS CoA Disconnect
- Moves device to restricted VLAN 90
- Confirmation prompt before blocking

#### Unblock Device (`/admin/device/<id>/unblock`)
- Sets device `registration_status` to 'active'
- Determines target VLAN from user's status (friars, staff, students, etc.)
- For WiFi devices: Re-registers MAC in Kea DHCP with appropriate VLAN
- For wired devices: Sends RADIUS CoA Change-of-Authorization
- Restores network access

#### Delete Device (`/admin/device/<id>/delete`)
- Unregisters device from network (Kea or RADIUS)
- Deletes device record from database
- Confirmation prompt before deletion

### 4. Visual VLAN Configuration Info
Dashboard displays two-panel configuration guide:

**Left Panel (Green):**
- Lists Auto-Approve VLANs with names
- Explains automatic registration behavior

**Right Panel (Orange):**
- Lists Admin-Approval VLANs with names
- Explains manual approval requirement

### 5. Pending Requests Section
Enhanced to show:
- Submission timestamp
- User's first and last name (instead of combined full_name)
- IP address in addition to MAC address
- Review button linking to approval page

## Code Changes

### `app/app.py`

**Constants Added:**
```python
AUTO_APPROVE_VLANS = [40, 30, 60]  # guests, students, volunteers
ADMIN_APPROVAL_VLANS = [10, 20, 50]  # friars, staff, contractors
```

**Modified Functions:**
- `register()` - Auto-approval logic based on VLAN
- `admin_dashboard()` - Enhanced query to join devices with users, pass VLAN config
- Added: `admin_block_device(device_id)` - Block device endpoint
- Added: `admin_unblock_device(device_id)` - Unblock device endpoint
- Added: `admin_delete_device(device_id)` - Delete device endpoint

### `app/templates/admin_dashboard.html`

**Updated Sections:**
- Added logout button to header
- Enhanced pending requests table with IP address column
- Completely redesigned device table with all new columns
- Added VLAN configuration panels with color-coded distinction
- Form buttons for block/unblock/delete actions with confirmation prompts
- Visual styling for blocked devices (red background)
- Status badges with appropriate colors

## Usage Instructions

### Accessing Admin Dashboard
1. Navigate to `http://192.168.10.4:8080/admin/login`
2. Login with admin credentials
3. Dashboard displays all sections

### Approving/Rejecting Registrations
1. View pending requests at top of dashboard
2. Click "Review" button
3. Choose approve or reject
4. For approval, set user status, dates, and notes
5. System creates user account and device record

### Managing Devices
1. Scroll to "All Registered Devices" section
2. Find device by MAC address or user name
3. Use action buttons:
   - **Block**: Immediately blocks access, moves to VLAN 90
   - **Unblock**: Restores access, returns to appropriate VLAN
   - **Delete**: Removes from system entirely

### Understanding Auto-Approval
- Devices on guest, student, volunteer VLANs are approved automatically
- No admin action needed for these VLANs
- User immediately gets access upon registration
- Admin can still block devices later if needed

### Understanding Manual Approval
- Devices on friar, staff, contractor VLANs require approval
- User submits registration and waits
- Admin receives email with approval link (if Microsoft Graph configured)
- Admin reviews and approves/rejects via dashboard or email link

## Network Behavior

### WiFi Devices (via Kea DHCP)
- **Blocked**: Kea host reservation removed, device moves to unregistered pool (.128-.254)
- **Active**: Kea host reservation created with appropriate VLAN client class
- **First Seen**: Populated from Kea lease file when MAC first detected
- **SSID**: Captured during registration (future: auto-detect from UniFi)

### Wired Devices (via RADIUS)
- **Blocked**: RADIUS CoA Disconnect sent to NAS
- **Active**: RADIUS CoA ChangeRequest sent with new VLAN
- **First Seen**: Timestamp when device first registered
- **SSID**: Not applicable (shows '-')

## Database Schema

### Devices Table
```sql
id SERIAL PRIMARY KEY
user_id INTEGER REFERENCES users(id)
mac_address VARCHAR(17) UNIQUE NOT NULL
ip_address VARCHAR(15)
connection_type VARCHAR(10)  -- 'wifi' or 'wired'
ssid VARCHAR(100)  -- WiFi network name
registration_status VARCHAR(20) DEFAULT 'pending'  -- 'active', 'blocked', 'pending'
registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
last_seen TIMESTAMP
first_seen TIMESTAMP  -- NEW: when device first connected
current_vlan INTEGER
unregister_token VARCHAR(255)
```

## Testing Steps

### Test Auto-Approval (VLAN 40 - Guests)
1. Connect device to guest WiFi (blac-onboarding)
2. Device gets unregistered IP (192.168.10.128-.254)
3. Visit http://192.168.10.4 (captive portal)
4. Submit registration form
5. Verify immediate approval (no pending request)
6. Check device appears in dashboard as "Active"
7. Verify device gets registered IP (.5-.127) on DHCP renewal
8. Test internet access

### Test Manual Approval (VLAN 20 - Staff)
1. Connect staff device to WiFi
2. Visit portal and submit registration
3. Verify appears in "Pending Requests"
4. Admin reviews and approves
5. User gets access
6. Verify device in dashboard as "Active"

### Test Block/Unblock
1. Find active device in dashboard
2. Click "Block" button, confirm
3. Verify device status changes to "Blocked"
4. Verify device loses network access
5. Click "Unblock" button
6. Verify device status changes to "Active"
7. Verify network access restored

### Test Delete
1. Find device to remove
2. Click "Delete" button, confirm
3. Verify device removed from table
4. Verify device disconnected from network
5. Verify database record deleted

## Known Issues

### Email Notifications
- Microsoft Graph not yet configured
- Approval emails not sent to admins
- WiFi confirmation emails not sent to users
- Auto-approval works but email notifications fail silently
- See `MICROSOFT_GRAPH_SETUP.md` for configuration instructions

### Health Check Error
- Portal logs show SQL health check warning
- Does not affect functionality
- Can be fixed by updating health endpoint to use SQLAlchemy text()

### First Seen Timestamp
- Currently populated when MAC first detected in Kea lease file
- Not retroactively populated for existing devices
- Consider migration script to set from registered_at for old devices

## Future Enhancements

### UniFi Integration
- Auto-detect SSID from UniFi controller
- Populate first_seen from UniFi client history
- Show signal strength and AP name
- Link to UniFi client details page

### Enhanced Filtering
- Search by MAC, name, email
- Filter by status (active/blocked/pending)
- Filter by VLAN
- Filter by connection type (WiFi/wired)
- Date range filtering for first_seen/last_seen

### Bulk Operations
- Checkboxes for multiple device selection
- Bulk block/unblock/delete
- Export to CSV

### Device Metadata
- Device hostname/description
- Browser/OS detection
- Connection history log
- Bandwidth usage stats

### Email Configuration
- Complete Microsoft Graph setup
- Template customization
- Admin notification preferences
- User welcome emails

## Configuration Files

### Environment Variables (`.env`)
```bash
# Auto-approval VLANs (comma-separated)
AUTO_APPROVE_VLANS=40,30,60

# VLANs requiring admin approval (comma-separated)
ADMIN_APPROVAL_VLANS=10,20,50
```

### VLAN Mappings (`app.py`)
```python
VLAN_MAP = {
    'friars': 10,
    'staff': 20,
    'students': 30,
    'guests': 40,
    'contractors': 50,
    'volunteers': 60,
    'iot': 70,
    'restricted': 90,
    'unregistered': 99
}
```

## Related Documentation
- `WIFI_THREE_POOL_IMPLEMENTATION.md` - DHCP pool configuration
- `KEA_CLIENT_CLASSES_GUIDE.md` - Kea client class setup
- `MICROSOFT_GRAPH_SETUP.md` - Email configuration
- `COA_SETUP.md` - RADIUS Change-of-Authorization
- `HP5130_WALLED_GARDEN.md` - Switch ACL configuration
- `DEPLOYMENT_GUIDE.md` - Full system deployment

## Deployment Status
✅ Code implemented  
✅ Database schema updated  
✅ Template updated  
✅ Container restarted  
⏳ Testing required  
⏳ Microsoft Graph configuration pending
