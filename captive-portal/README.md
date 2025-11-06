# Captive Portal for Network Access Control

A comprehensive captive portal solution for network device registration with RADIUS integration, VLAN assignment, and email verification.

## Features

- **User Registration Portal**: Simple web interface for users to register devices
- **Pre-Authorization**: Network administrators can pre-register users with access levels and dates
- **Email Verification**: Optional email verification before granting full access
- **Admin Dashboard**: Web-based admin panel for user and device management
- **RADIUS CoA Integration**: Automatic VLAN assignment via RADIUS Change-of-Authorization
- **Multiple Access Levels**: Support for different user statuses (staff, students, guests, etc.)
- **Request Approval Workflow**: Admin can approve requests from unknown users
- **Containerized**: Everything runs in Docker containers

## Architecture

```
User Device → HP5130 Switch → RADIUS (MAC Auth) → VLAN 99 (Registration)
                ↓
          Captive Portal (Web)
                ↓
          Registration/Verification
                ↓
          RADIUS CoA → Move to Appropriate VLAN
```

## Components

1. **Web Application** (Flask): Captive portal and admin interface
2. **PostgreSQL**: Database for users, devices, and registration requests
3. **Redis**: Session storage and caching
4. **RADIUS Server** (FreeRADIUS): MAC authentication and CoA
5. **NPM** (Nginx Proxy Manager): Reverse proxy with SSL

## VLAN Structure

| Status | VLAN ID | Description |
|--------|---------|-------------|
| friars | 10 | Friars network |
| staff | 20 | Staff network |
| students | 30 | Students network |
| guests | 40 | Guests network |
| contractors | 50 | Contractors network |
| volunteers | 60 | Volunteers network |
| iot | 70 | IoT devices |
| restricted | 90 | Restricted access (failed verification) |
| unregistered | 99 | Registration/captive portal VLAN |

## Installation

### 1. Prerequisites

- Raspberry Pi (or Linux server) with Docker and Docker Compose
- HP5130 switch configured for MAC authentication
- FreeRADIUS configured for MAC authentication
- Network connectivity between Pi, switch, and devices

### 2. Clone or Copy Files

The captive portal is in the `captive-portal/` directory with the following structure:

```
captive-portal/
├── docker-compose.yml
├── .env.example
├── init-db.sql
└── app/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py
    ├── models.py
    ├── radius_coa.py
    ├── email_service.py
    └── templates/
        ├── base.html
        ├── register.html
        ├── status.html
        ├── admin_login.html
        ├── admin_dashboard.html
        ├── admin_add_user.html
        ├── admin_edit_user.html
        └── admin_approve_request.html
```

### 3. Configure Environment

```bash
cd captive-portal
cp .env.example .env
nano .env
```

Edit `.env` with your settings:

```bash
# Database password
DB_PASSWORD=your_secure_password

# Secret key for Flask (generate with: python -c 'import secrets; print(secrets.token_hex(32))')
SECRET_KEY=your_secret_key_here

# SMTP settings (for Gmail, use app password)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM=noreply@yourdomain.com
ADMIN_EMAIL=admin@yourdomain.com

# RADIUS settings
RADIUS_SECRET=testing123
RADIUS_SERVER=192.168.99.4
RADIUS_NAS_IP=192.168.99.1

# Portal URL (will be set up with NPM)
PORTAL_URL=https://portal.yourdomain.com

# Security settings
EMAIL_VERIFICATION_REQUIRED=false
VERIFICATION_TIMEOUT_MINUTES=15
```

### 4. Start Services

```bash
docker-compose up -d
```

Check logs:
```bash
docker-compose logs -f
```

### 5. Configure Nginx Proxy Manager

1. Access NPM admin interface (usually at `http://raspberry-pi-ip:81`)
2. Add a new Proxy Host:
   - **Domain Names**: `portal.yourdomain.com` (or use IP for testing)
   - **Scheme**: `http`
   - **Forward Hostname/IP**: `captive-portal-web` (or Pi's IP)
   - **Forward Port**: `8080`
   - **SSL**: Enable if you have a domain and want SSL

3. (Optional) For captive portal detection, you may also want to set up:
   - Proxy host for `captiveportal.apple.com` → your portal
   - Proxy host for `connectivitycheck.gstatic.com` → your portal

### 6. Configure FreeRADIUS for CoA

Edit FreeRADIUS configuration to enable CoA:

**File: `/etc/raddb/sites-enabled/coa`** (or create it):

```
server coa {
    listen {
        type = coa
        ipaddr = *
        port = 3799
    }

    recv-coa {
        ok
    }

    send-coa {
        ok
    }
}
```

**File: `/etc/raddb/clients.conf`** - Add captive portal as a client:

```
client captive-portal {
    ipaddr = 192.168.99.4
    secret = testing123
    coa_server = yes
}
```

Restart FreeRADIUS:
```bash
docker-compose -f ../freeradius/docker-compose.yml restart
```

### 7. DNS/Captive Portal Detection

For automatic captive portal detection, configure your DNS server or router to redirect captive portal detection domains to your portal:

- `captiveportal.apple.com` → your portal IP
- `connectivitycheck.gstatic.com` → your portal IP
- `www.msftconnecttest.com` → your portal IP

Alternatively, use iptables rules on the Pi to redirect HTTP traffic from VLAN 99.

## Usage

### For Network Administrators

#### 1. Access Admin Panel

Navigate to `https://portal.yourdomain.com/admin/login`

Default credentials:
- Username: `admin`
- Password: `admin123`

**⚠️ IMPORTANT**: Change the default admin password immediately!

To set a custom password, generate a hash:
```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your_new_password'))"
```

Then add to `.env`:
```bash
ADMIN_PASSWORD_HASH='the_hash_you_generated'
```

#### 2. Pre-Register Users (Scenario 1)

1. Click "Add New User"
2. Fill in:
   - Email address (required)
   - Name and phone (optional)
   - Access level (status)
   - Begin and expiry dates
3. Save

When the user connects and registers, they'll automatically get access if:
- They use the correct email address
- Current date is within their access period

#### 3. Approve Registration Requests (Scenario 2)

When an unknown user tries to register:
1. You receive an email notification
2. Click the link in the email or go to admin dashboard
3. Review the request details
4. Contact the user to verify identity
5. Approve with appropriate access level and dates
6. The user's device is immediately moved to the correct VLAN

### For End Users

#### Registering a Device

1. Connect to WiFi or plug into an Ethernet port (GigabitEthernet1/0/19 or 1/0/21)
2. Device is placed on VLAN 99 (unregistered)
3. Try to access any website - you'll be redirected to the captive portal
4. Fill in the registration form:
   - Email address
   - First and last name
   - Phone number (optional)
5. Submit

**If pre-registered:**
- Email verification may be required (check email)
- Or immediately get access if verification is disabled
- Device moves to appropriate VLAN based on status

**If not pre-registered:**
- See a message that admin will review
- Admin receives email notification
- Wait for admin to approve
- Once approved, device gets access

#### Checking Status

Navigate to the status page to see:
- Current registration status
- Access level
- VLAN assignment
- Expiry date

## Configuration Options

### Email Verification

Set in `.env`:
```bash
EMAIL_VERIFICATION_REQUIRED=true  # or false
VERIFICATION_TIMEOUT_MINUTES=15
```

When enabled:
- User receives verification email after registration
- Must click link within timeout period
- If expired, device moves to restricted VLAN (90)

### VLAN Mappings

Edit VLAN IDs in `.env`:
```bash
VLAN_FRIARS=10
VLAN_STAFF=20
# etc.
```

### SMTP Settings

For Gmail:
1. Enable 2FA on your Google account
2. Generate an "App Password"
3. Use the app password in `SMTP_PASSWORD`

For other email providers, adjust `SMTP_HOST` and `SMTP_PORT`.

## Troubleshooting

### Captive Portal Not Appearing

1. **Check DNS**: Ensure captive portal detection domains redirect to portal
2. **Check routing**: VLAN 99 devices should be able to reach the portal
3. **Check NPM**: Verify proxy host is configured correctly
4. **Check firewall**: Ensure port 8080 (or 80/443 via NPM) is accessible

### CoA Not Working

1. **Check FreeRADIUS**: Ensure CoA server is enabled
2. **Check client config**: Captive portal must be defined as a client in FreeRADIUS
3. **Check secret**: RADIUS_SECRET must match in both places
4. **Check logs**: `docker-compose logs web` for CoA errors

### Device Not Getting MAC Address

The portal tries to detect MAC from:
- `X-Client-MAC` header
- `mac` query parameter
- `mac` form field

You may need to:
- Configure your switch to pass MAC in HTTP headers
- Use DHCP option 82 and configure accordingly
- Pass MAC in the redirect URL

### Email Not Sending

1. **Check SMTP settings**: Verify host, port, username, password
2. **Check logs**: `docker-compose logs web` for email errors
3. **Test SMTP**: Use a simple Python script to test SMTP connection
4. **Check firewall**: Ensure outbound SMTP port is open

## Security Considerations

1. **Change default admin password** immediately
2. **Use HTTPS** (configure SSL in NPM)
3. **Secure the database** (change DB_PASSWORD)
4. **Restrict admin access** (firewall, VPN, etc.)
5. **Regular updates** (update Docker images)
6. **Secure email** (use app passwords, not account passwords)
7. **Monitor logs** regularly for suspicious activity

## Network Configuration

### HP5130 Switch Configuration

Your current config already has MAC authentication enabled on ports. Ensure:

1. **VLAN 99** is accessible from registration ports
2. **RADIUS server** is properly configured (already done)
3. **CoA** is supported and enabled

### UniFi AP Configuration

If using UniFi AP:
1. Configure SSIDs for different VLANs
2. Enable "Guest Portal" redirect (optional)
3. Set RADIUS profile for MAC authentication

## Maintenance

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f web
docker-compose logs -f db
```

### Backup Database

```bash
docker-compose exec db pg_dump -U portal_user captive_portal > backup.sql
```

### Restore Database

```bash
docker-compose exec -T db psql -U portal_user captive_portal < backup.sql
```

### Update Application

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Advanced Configuration

### Custom VLAN Assignment Logic

Edit `app/app.py` to customize VLAN assignment based on:
- Time of day
- Device type
- Number of active devices
- Custom business logic

### Integration with External Systems

The portal can be extended to integrate with:
- Active Directory / LDAP
- Student information systems
- HR systems
- Custom authentication providers

### API Endpoints

The portal exposes a `/health` endpoint for monitoring. Additional API endpoints can be added for:
- Device registration via API
- Status queries
- Admin operations

## Support

For issues specific to:
- **HP5130 Switch**: Check HP documentation for MAC authentication
- **FreeRADIUS**: Check FreeRADIUS documentation and logs
- **Docker**: Check Docker and Docker Compose logs
- **This Portal**: Check application logs in `docker-compose logs web`

## License

This captive portal is provided as-is for your network infrastructure needs.

## Changelog

### Version 1.0.0 (2025-11-05)
- Initial release
- User registration portal
- Admin dashboard
- RADIUS CoA integration
- Email verification
- Request approval workflow
- Multiple VLAN support
