# Admin Dashboard Implementation

## Overview
Enhanced the captive portal admin dashboard with comprehensive device management capabilities and differentiated approval workflows.

## Features Implemented

### 1. VLAN Configuration
VLAN mappings and auto-approval settings are fully configurable through the admin interface at `/admin/vlan-config`. 

Administrators can:
- Set VLAN IDs for each user status (friars, staff, students, guests, contractors, volunteers, iot, restricted, unregistered)
- Enable/disable auto-approval for each VLAN
- VLANs with auto-approval enabled: devices are automatically registered and granted access
- VLANs without auto-approval: registration requests require manual admin review and approval

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

### 4. VLAN Configuration Management
Dedicated configuration page at `/admin/vlan-config` provides:

**VLAN Mapping:**
- Editable VLAN ID for each user status
- Input validation (VLAN IDs 1-4094)

**Auto-Approval Settings:**
- Checkbox for each status to enable/disable auto-approval
- Visual indicators showing current configuration
- Restricted and unregistered VLANs cannot be auto-approved (system restriction)

### 5. Pending Requests Section
Enhanced to show:
- Submission timestamp
- User's first and last name (instead of combined full_name)
- IP address in addition to MAC address
- Review button linking to approval page

## Code Changes

### `app/app.py`

**Database-Backed Configuration Functions:**
```python
get_vlan_map()  # Loads VLAN mappings from database
get_auto_approve_vlans()  # Loads auto-approval VLAN list from settings
get_admin_approval_vlans()  # Loads admin-required VLAN list from settings
```

**Modified Functions:**
- `register()` - Auto-approval logic based on VLAN (uses get_auto_approve_vlans())
- `admin_dashboard()` - Enhanced query to join devices with users, pass VLAN config
- `admin_vlan_config()` - GET/POST endpoint for VLAN configuration management
- `admin_block_device(device_id)` - Block device endpoint
- `admin_unblock_device(device_id)` - Unblock device endpoint
- `admin_delete_device(device_id)` - Delete device endpoint

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

### Configuring VLAN Settings
1. Click "⚙️ VLAN Configuration" button in admin dashboard
2. Edit VLAN IDs for each user status
3. Check/uncheck auto-approval for each status
4. Click "Save Configuration"
5. Changes take effect immediately for new registrations

### Understanding Auto-Approval
- VLANs with auto-approval enabled: Users are immediately registered and granted access
- No admin action needed for auto-approved VLANs
- User status is automatically assigned based on VLAN
- Admin can still block devices later if needed

### Understanding Manual Approval
- VLANs without auto-approval: Registration creates a pending request
- User submits registration and waits
- Admin receives email with approval link (if Microsoft Graph configured)
- Admin reviews and approves/rejects via dashboard or email link
- Admin can assign appropriate status during approval

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

### Test VLAN Configuration
1. Navigate to `/admin/vlan-config`
2. Modify VLAN IDs for different statuses
3. Enable/disable auto-approval checkboxes
4. Save configuration
5. Verify changes persist after page reload
6. Test registration on different VLANs

### Test Auto-Approval (for VLANs with auto-approval enabled)
1. Enable auto-approval for a VLAN in configuration page
2. Connect device to that VLAN's WiFi
3. Visit portal and submit registration form
4. Verify immediate approval (no pending request)
5. Check device appears in dashboard as "Active"
6. Verify correct user status assigned based on VLAN
7. Test network access

### Test Manual Approval (for VLANs without auto-approval)
1. Disable auto-approval for a VLAN in configuration page
2. Connect device to that VLAN's WiFi
3. Visit portal and submit registration
4. Verify appears in "Pending Requests"
5. Admin reviews and approves with appropriate status
6. User gets access
7. Verify device in dashboard as "Active"

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

## Configuration

### VLAN Configuration (Database-Backed)
All VLAN configuration is stored in the database and managed through the web interface at `/admin/vlan-config`:

**VlanMapping Table:**
- Stores status → VLAN ID mappings
- Editable through admin interface

**Settings Table:**
- `auto_approve_vlans`: Comma-separated list of VLAN IDs that auto-approve
- `admin_approval_vlans`: Automatically calculated as inverse of auto_approve_vlans

**Default Fallback (if database empty):**
```python
VLAN_MAP = {
    'friars': 10, 'staff': 20, 'students': 30, 'guests': 40,
    'contractors': 50, 'volunteers': 60, 'iot': 70,
    'restricted': 90, 'unregistered': 99
}
auto_approve_vlans = '40,30,60'  # guests, students, volunteers
```

### Environment Variables (`.env`)
No VLAN configuration needed in environment variables. All configuration is database-backed and managed through the web UI.

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
