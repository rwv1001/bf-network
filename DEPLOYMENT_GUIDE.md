# Complete Captive Portal Deployment Guide

## System Overview

You now have a complete captive portal solution with:

- **Captive Portal Web Application** (Flask + PostgreSQL)
- **RADIUS CoA Integration** (FreeRADIUS with Change-of-Authorization)
- **Email Notifications** (SMTP integration)
- **Admin Dashboard** (User and device management)
- **Automatic VLAN Assignment** (Based on user status)
- **Two Registration Workflows** (Pre-authorized and request-approval)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Network Flow                             │
└─────────────────────────────────────────────────────────────────┘

Device connects to WiFi/Ethernet
        ↓
HP5130 Switch (MAC Authentication)
        ↓
RADIUS Server (192.168.99.4:1812)
        ↓
Assigns VLAN 99 (Registration VLAN)
        ↓
Device gets IP via Kea DHCP
        ↓
User opens browser → Redirected to Captive Portal
        ↓
User fills registration form
        ↓
┌──────────────────────────────────┬──────────────────────────────┐
│  Pre-Authorized User?            │  Unknown User?               │
├──────────────────────────────────┼──────────────────────────────┤
│  ✓ Email in database             │  ✗ Email not in database     │
│  ✓ Dates valid                   │  → Create registration req   │
│  → Grant access                  │  → Email admin               │
│  → Send CoA to RADIUS            │  → Wait for approval         │
│  → Move to status VLAN           │                              │
└──────────────────────────────────┴──────────────────────────────┘
        ↓
RADIUS CoA (192.168.99.4:3799)
        ↓
HP5130 receives CoA
        ↓
Device disconnected/reconnected to new VLAN
        ↓
Full network access granted
```

## Deployment Steps

### Phase 1: Initial Setup (15 minutes)

#### 1.1 Deploy Captive Portal

```bash
cd /home/admin/bf-network/captive-portal
./setup.sh
```

This will:
- Create `.env` with generated secrets
- Start all Docker containers
- Initialize database
- Display access URLs

#### 1.2 Configure Environment

Edit `.env` for your environment:

```bash
nano .env
```

**Required settings:**
```bash
# Email (required for notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=portal@yourdomain.com
ADMIN_EMAIL=admin@yourdomain.com

# Portal URL (required for email links)
PORTAL_URL=https://portal.yourdomain.com
```

**Optional settings:**
```bash
# Email verification (disable for easier testing)
EMAIL_VERIFICATION_REQUIRED=false

# Or enable for production security
EMAIL_VERIFICATION_REQUIRED=true
VERIFICATION_TIMEOUT_MINUTES=15
```

Restart after changes:
```bash
docker-compose restart
```

#### 1.3 Configure FreeRADIUS CoA

```bash
cd /home/admin/bf-network/freeradius
docker-compose restart
docker-compose logs -f | grep -i coa
```

Should see: `Listening on coa address * port 3799`

#### 1.4 Verify Services

```bash
# Check captive portal
curl http://192.168.99.4:8080/health
# Expected: {"status":"healthy"}

# Check database
cd /home/admin/bf-network/captive-portal
docker-compose exec db psql -U portal_user -d captive_portal -c "\dt"
# Should list tables: users, devices, registration_requests, etc.

# Check RADIUS CoA port
netstat -uln | grep 3799
# Should show: udp 0 0 0.0.0.0:3799
```

### Phase 2: Network Configuration (30 minutes)

#### 2.1 Configure NPM (Nginx Proxy Manager)

Access NPM at: `http://192.168.99.4:81`

**Add Proxy Host:**
```
Domain Names: portal.yourdomain.com (or use IP for testing)
Scheme: http
Forward Hostname/IP: 192.168.99.4
Forward Port: 8080
Cache Assets: No
Block Common Exploits: Yes
Websockets Support: No

SSL:
- Request Let's Encrypt certificate (if using domain)
- Force SSL (if using domain)
```

**For Captive Portal Detection:**

Add additional proxy hosts for:
```
captiveportal.apple.com → 192.168.99.4:8080
connectivitycheck.gstatic.com → 192.168.99.4:8080
www.msftconnecttest.com → 192.168.99.4:8080
```

OR use DNS redirection (easier):

#### 2.2 Configure DNS (Alternative to NPM redirects)

If you control your DNS server, add A records:
```
portal.yourdomain.com → 192.168.99.4
captiveportal.apple.com → 192.168.99.4
connectivitycheck.gstatic.com → 192.168.99.4
```

#### 2.3 Configure Firewall (if enabled)

```bash
# Allow captive portal access
sudo ufw allow 8080/tcp

# Allow RADIUS CoA
sudo ufw allow 3799/udp

# Allow HTTP/HTTPS (if not using NPM)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

#### 2.4 Verify HP5130 Configuration

Your switch is already configured with:
- ✓ MAC authentication enabled
- ✓ VLAN 99 as default (check ports 19, 21)
- ✓ RADIUS server configured (192.168.99.4)
- ✓ Multiple VLANs configured

**Verify VLAN 99 connectivity:**
```bash
# From a device on VLAN 99, should be able to reach:
ping 192.168.99.4  # Pi
curl http://192.168.99.4:8080  # Portal
```

### Phase 3: Testing (30 minutes)

#### 3.1 Access Admin Panel

1. Navigate to: `http://192.168.99.4:8080/admin/login`
2. Login with: `admin` / `admin123`
3. **Immediately change password!**

#### 3.2 Create Test User (Pre-Authorized Flow)

**In Admin Panel:**
```
Click: "Add New User"
Fill in:
  Email: test.user@example.com
  First Name: Test
  Last Name: User
  Status: guests
  Begin Date: today
  Expiry Date: +30 days
Click: "Add User"
```

#### 3.3 Test Registration Flow

**From a test device:**

1. Connect to WiFi AP or plug into port GigabitEthernet1/0/19
2. Device should get DHCP on VLAN 99 (192.168.99.x)
3. Open browser → try to visit any website
4. Should redirect to captive portal
5. Fill in registration form:
   - Email: test.user@example.com
   - First Name: Test
   - Last Name: User
6. Submit
7. Should see success message
8. Device should disconnect/reconnect to VLAN 40 (guests)
9. Get new IP on VLAN 40 (192.168.40.x)
10. Now have full internet access

**Check in Admin Panel:**
- User's device should appear under "Recent Devices"
- Status: active
- VLAN: 40

#### 3.4 Test Unknown User Flow

**From another test device:**

1. Connect to network (VLAN 99)
2. Visit captive portal
3. Fill form with NEW email: new.user@example.com
4. Submit
5. Should see: "Request submitted, admin will review"

**Check Admin Email:**
- Should receive notification email
- Click link to approve request

**Approve in Admin Panel:**
1. Set status: students
2. Set dates: today to +90 days
3. Click "Approve and Activate"
4. Device immediately moves to VLAN 30 (students)

#### 3.5 Test Email Verification (if enabled)

Enable in `.env`:
```bash
EMAIL_VERIFICATION_REQUIRED=true
```

Restart:
```bash
docker-compose restart
```

**Test flow:**
1. Pre-authorize a user with an email you can check
2. Register from device
3. Check email for verification link
4. Click link within timeout (15 minutes)
5. Device moves to correct VLAN

**Test timeout:**
1. Register but don't click link
2. Wait 15+ minutes
3. Device should move to VLAN 90 (restricted)

### Phase 4: Production Preparation

#### 4.1 Security Checklist

- [ ] Change admin password
- [ ] Change database password (in .env)
- [ ] Generate strong SECRET_KEY
- [ ] Change RADIUS secret (in both FreeRADIUS and portal)
- [ ] Enable HTTPS via NPM
- [ ] Restrict admin access (firewall rules)
- [ ] Review .env file - no defaults left
- [ ] Set up regular database backups

**Change Admin Password:**

Generate hash:
```bash
cd /home/admin/bf-network/captive-portal
docker-compose exec web python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YourNewSecurePassword123!'))"
```

Add to `.env`:
```bash
ADMIN_PASSWORD_HASH='pbkdf2:sha256:...'
```

Restart:
```bash
docker-compose restart
```

#### 4.2 Configure Email

**For Gmail:**
1. Enable 2FA on Google account
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Use app password in `SMTP_PASSWORD`

**For other providers:**
Adjust `SMTP_HOST` and `SMTP_PORT` accordingly.

**Test email:**
```bash
docker-compose exec web python -c "
from email_service import send_email
result = send_email('your-test-email@example.com', 'Test', '<p>Test email from portal</p>')
print('Success!' if result else 'Failed')
"
```

#### 4.3 Set Up Backups

**Database Backup Script:**

Create `/home/admin/backup-portal.sh`:
```bash
#!/bin/bash
BACKUP_DIR="/home/admin/backups/captive-portal"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

cd /home/admin/bf-network/captive-portal
docker-compose exec -T db pg_dump -U portal_user captive_portal | \
  gzip > "$BACKUP_DIR/portal_${DATE}.sql.gz"

# Keep last 30 days
find "$BACKUP_DIR" -name "portal_*.sql.gz" -mtime +30 -delete

echo "Backup completed: portal_${DATE}.sql.gz"
```

Make executable and add to crontab:
```bash
chmod +x /home/admin/backup-portal.sh
crontab -e
```

Add:
```
0 2 * * * /home/admin/backup-portal.sh
```

**Restore from backup:**
```bash
cd /home/admin/bf-network/captive-portal
gunzip < /home/admin/backups/captive-portal/portal_YYYYMMDD_HHMMSS.sql.gz | \
  docker-compose exec -T db psql -U portal_user captive_portal
```

#### 4.4 Monitoring

**Check services daily:**
```bash
cd /home/admin/bf-network/captive-portal
docker-compose ps
docker-compose logs --tail=100
```

**Watch for errors:**
```bash
docker-compose logs -f | grep -i error
```

**Monitor CoA:**
```bash
docker-compose logs -f | grep -i coa
```

### Phase 5: Ongoing Operations

#### Adding Users

**Bulk Add Users:**

Create CSV file `users.csv`:
```
email,first_name,last_name,status,begin_date,expiry_date
john.doe@example.com,John,Doe,staff,2025-11-05,2026-11-05
jane.smith@example.com,Jane,Smith,students,2025-11-05,2026-06-30
```

Import script:
```bash
docker-compose exec web python << 'EOF'
import csv
from app import app, db
from models import User
from datetime import datetime

with app.app_context():
    with open('/app/users.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            user = User(
                email=row['email'],
                first_name=row['first_name'],
                last_name=row['last_name'],
                status=row['status'],
                begin_date=datetime.strptime(row['begin_date'], '%Y-%m-%d').date(),
                expiry_date=datetime.strptime(row['expiry_date'], '%Y-%m-%d').date()
            )
            db.session.add(user)
        db.session.commit()
        print(f"Imported {reader.line_num - 1} users")
EOF
```

#### Managing Devices

**List all active devices:**
```bash
docker-compose exec db psql -U portal_user -d captive_portal -c \
  "SELECT mac_address, email, status, current_vlan FROM devices 
   JOIN users ON devices.user_id = users.id 
   WHERE registration_status = 'active' 
   ORDER BY registered_at DESC;"
```

**Disconnect device:**
Via admin panel or:
```bash
docker-compose exec web python << 'EOF'
from app import app
from radius_coa import send_coa_disconnect

with app.app_context():
    success = send_coa_disconnect('aa:bb:cc:dd:ee:ff')
    print('Disconnected' if success else 'Failed')
EOF
```

#### Updating Access Levels

**Change user status:**
1. Admin panel → Edit user → Change status
2. All user's devices automatically update

**Extend expiry date:**
1. Admin panel → Edit user → Change expiry date
2. Save

#### Troubleshooting

**Device stuck on VLAN 99:**
1. Check portal logs: `docker-compose logs web | grep -i error`
2. Check CoA: `docker-compose logs web | grep -i coa`
3. Check FreeRADIUS: `docker-compose -f ../freeradius/docker-compose.yml logs | grep -i coa`
4. Manual CoA test:
   ```bash
   echo "Calling-Station-Id = \"AA-BB-CC-DD-EE-FF\"" | \
     radclient 192.168.99.4:3799 coa testing123
   ```

**Portal not accessible:**
1. Check services: `docker-compose ps`
2. Check health: `curl http://localhost:8080/health`
3. Check logs: `docker-compose logs web`
4. Restart: `docker-compose restart`

**Email not sending:**
1. Check SMTP settings in `.env`
2. Test SMTP: `docker-compose exec web python -c "from email_service import send_email; send_email('test@example.com', 'Test', 'Test')"`
3. Check logs: `docker-compose logs web | grep -i email`

## Customization

### Branding

Edit templates in `app/templates/` to customize:
- Colors (in `base.html` CSS)
- Logo and branding
- Welcome messages
- Footer text

### VLAN Mappings

To change VLAN assignments, edit `.env`:
```bash
VLAN_STAFF=25  # Change from 20 to 25
```

Restart:
```bash
docker-compose restart
```

### Email Templates

Edit `app/email_service.py` to customize email content and styling.

### Custom Fields

To add custom fields (e.g., employee ID):
1. Update database: Add column to `users` table
2. Update model: Add field to `User` class in `models.py`
3. Update forms: Add input to templates
4. Update routes: Handle new field in `app.py`

## Integration Ideas

### Active Directory/LDAP

Replace email validation with AD/LDAP lookup:
- Install `python-ldap` package
- Add LDAP config to `.env`
- Update registration logic to query AD

### Student Information System

Integrate with SIS for automatic student data:
- Add API endpoint to portal
- SIS pushes/pulls user data
- Automatic status updates

### Slack/Teams Notifications

Send admin notifications to Slack/Teams instead of email:
- Add webhook URL to `.env`
- Update `email_service.py` to post to webhook

## Support Resources

- **Captive Portal Logs**: `/home/admin/bf-network/captive-portal/` → `docker-compose logs`
- **FreeRADIUS Logs**: `/home/admin/bf-network/freeradius/` → `docker-compose logs`
- **Database**: PostgreSQL on port 5432 (internal to Docker network)
- **Admin Panel**: `http://192.168.99.4:8080/admin/login`

## Success Criteria

Your captive portal is working correctly when:

✓ New devices connect and get VLAN 99
✓ Portal appears when browsing
✓ Pre-authorized users register and move to correct VLAN
✓ Unknown users trigger admin notification
✓ Admin can approve requests
✓ Devices successfully move between VLANs
✓ Email notifications work
✓ Admin panel accessible and functional
✓ Logs show no errors

Congratulations! You now have a fully functional captive portal with RADIUS integration.
