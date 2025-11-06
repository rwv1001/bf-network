# Captive Portal - Quick Setup Guide

## Quick Start (5 minutes)

### 1. Configure Environment
```bash
cd /home/admin/bf-network/captive-portal
cp .env.example .env
nano .env
```

Minimum required settings:
- `DB_PASSWORD` - Set a secure password
- `SECRET_KEY` - Generate with: `openssl rand -hex 32`
- `ADMIN_EMAIL` - Your admin email

### 2. Start Services
```bash
docker-compose up -d
```

### 3. Access Portal
- User portal: `http://192.168.99.4:8080`
- Admin login: `http://192.168.99.4:8080/admin/login`
- Default admin credentials: `admin` / `admin123`

### 4. Configure NPM Proxy
In Nginx Proxy Manager (port 81):
- Add proxy host pointing to `192.168.99.4:8080`
- Use domain name or IP address
- Enable SSL if you have a domain

## Workflow Examples

### Pre-Registered User Flow

1. **Admin adds user:**
   ```
   Email: john.doe@example.com
   Status: staff
   Dates: 2025-11-01 to 2026-11-01
   ```

2. **User connects device:**
   - Device gets DHCP on VLAN 99
   - Captive portal appears
   - User enters: john.doe@example.com + name
   
3. **System checks:**
   - Email found in database ✓
   - Date is valid ✓
   - Email verification disabled → immediate access
   
4. **Result:**
   - Device moved to VLAN 20 (staff)
   - Full network access granted

### Unknown User Flow

1. **User connects device:**
   - Device gets DHCP on VLAN 99
   - Captive portal appears
   - User enters: jane.smith@example.com + phone
   
2. **System creates request:**
   - Registration request saved
   - Admin email sent with approval link
   
3. **Admin receives email:**
   - Clicks link to review
   - Calls/emails Jane to verify
   - Approves with status: guests, dates: today to +30 days
   
4. **Result:**
   - User created in database
   - Device moved to VLAN 40 (guests)
   - Jane notified via email

## Common Tasks

### Add a Pre-Registered User
```
Admin Panel → Add New User → Fill form → Save
```

### Check Device Status
```
Admin Panel → Recent Devices section
```

### Approve Pending Request
```
Admin Panel → Pending Registration Requests → Review
OR
Click link in admin notification email
```

### Disconnect a Device
```
Admin Panel → Recent Devices → Find device → Disconnect
```

### Change User Access Level
```
Admin Panel → Authorized Users → Edit → Change status → Save
(All user's devices automatically moved to new VLAN)
```

## Testing

### Test User Registration (with pre-registered user)

1. Add test user in admin panel:
   ```
   Email: test@test.com
   Status: guests
   Begin: today
   Expiry: +30 days
   ```

2. From a device on VLAN 99, visit: `http://192.168.99.4:8080`

3. Fill registration form with `test@test.com`

4. Check admin panel - device should appear as "active" on VLAN 40

### Test Registration Request (unknown user)

1. From a device on VLAN 99, visit portal

2. Fill form with new email (not in database)

3. Check admin panel - should see pending request

4. Check admin email - should receive notification

5. Approve request → device should get access

## Troubleshooting Quick Checks

### Portal not accessible
```bash
docker-compose ps  # Check all services are "Up"
docker-compose logs web  # Check for errors
curl http://localhost:8080/health  # Should return {"status":"healthy"}
```

### Database issues
```bash
docker-compose logs db
docker-compose exec db psql -U portal_user -d captive_portal -c "\dt"
```

### CoA not working
```bash
docker-compose logs web | grep CoA
# Check FreeRADIUS logs
docker-compose -f ../freeradius/docker-compose.yml logs | grep CoA
```

### Email not sending
```bash
docker-compose logs web | grep -i email
# Check SMTP settings in .env
# Test with: docker-compose exec web python -c "from email_service import send_email; print(send_email('test@example.com', 'Test', '<p>Test</p>'))"
```

## Network Flow

```
Device connects
    ↓
MAC Auth via RADIUS
    ↓
RADIUS assigns VLAN 99 (authorize file DEFAULT rule)
    ↓
Device gets IP on VLAN 99
    ↓
Device tries to access internet → redirect to captive portal
    ↓
User fills registration form
    ↓
Portal validates user/creates request
    ↓
Portal sends RADIUS CoA
    ↓
RADIUS tells switch to change VLAN
    ↓
Device disconnected/reconnected to new VLAN
    ↓
Device gets new IP on target VLAN
    ↓
Full network access granted
```

## File Locations

- **Configuration**: `/home/admin/bf-network/captive-portal/.env`
- **Database data**: `/home/admin/bf-network/captive-portal/data/postgres/`
- **Application code**: `/home/admin/bf-network/captive-portal/app/`
- **Docker Compose**: `/home/admin/bf-network/captive-portal/docker-compose.yml`
- **Logs**: `docker-compose logs` (ephemeral)

## Integration Points

### With FreeRADIUS
- Portal reads: Current VLAN assignments (via authorize file logic)
- Portal writes: CoA packets to port 3799
- FreeRADIUS must have portal as CoA client

### With HP5130 Switch
- Switch sends: MAC auth requests to RADIUS
- Switch receives: CoA packets from RADIUS
- Switch must support CoA (HP5130 does)

### With Kea DHCP
- Separate system - DHCP assigned based on VLAN
- No direct integration needed
- Each VLAN has its own DHCP scope in kea config

### With NPM
- NPM provides: SSL termination, domain mapping
- Portal runs: HTTP on port 8080
- NPM forwards: HTTPS/HTTP → portal:8080

## Next Steps

1. **Test thoroughly** with various scenarios
2. **Configure SSL** in NPM for production
3. **Set up DNS** for captive portal detection
4. **Enable email verification** if needed
5. **Customize** branding and messages
6. **Set up monitoring** and alerting
7. **Create backup** procedures
8. **Document** your specific VLAN/user policies

## Production Checklist

- [ ] Changed default admin password
- [ ] Configured strong DB_PASSWORD
- [ ] Generated secure SECRET_KEY
- [ ] Configured SMTP for email
- [ ] Enabled HTTPS via NPM
- [ ] Tested user registration flow
- [ ] Tested admin approval flow
- [ ] Tested RADIUS CoA
- [ ] Verified VLAN assignments work
- [ ] Set up database backups
- [ ] Configured firewall rules
- [ ] Tested captive portal detection
- [ ] Documented your setup
