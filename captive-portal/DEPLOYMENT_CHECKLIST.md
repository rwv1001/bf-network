# Captive Portal - Pre-Deployment Checklist

Use this checklist to ensure your captive portal is properly configured before going live.

## Phase 1: Initial Setup ✓

- [ ] Run setup script: `cd captive-portal && ./setup.sh`
- [ ] Verify all containers are running: `docker-compose ps`
- [ ] Check health endpoint: `curl http://localhost:8080/health`
- [ ] Database tables created: `docker-compose exec db psql -U portal_user -d captive_portal -c "\dt"`

## Phase 2: Configuration

### Environment Variables (.env)

- [ ] `DB_PASSWORD` - Set secure password (not default)
- [ ] `SECRET_KEY` - Generated secure key (32+ characters)
- [ ] `SMTP_HOST` - Configured for your email provider
- [ ] `SMTP_PORT` - Set correctly (587 for TLS, 465 for SSL)
- [ ] `SMTP_USER` - Valid email account
- [ ] `SMTP_PASSWORD` - App password or account password
- [ ] `SMTP_FROM` - From address for emails
- [ ] `ADMIN_EMAIL` - Your admin email for notifications
- [ ] `RADIUS_SECRET` - Matches FreeRADIUS secret
- [ ] `RADIUS_SERVER` - Set to 192.168.99.4
- [ ] `RADIUS_NAS_IP` - Set to 192.168.99.1 (HP5130)
- [ ] `PORTAL_URL` - Set to your portal URL (for email links)
- [ ] `EMAIL_VERIFICATION_REQUIRED` - Set to true/false
- [ ] Restart after changes: `docker-compose restart`

### Admin Account

- [ ] Can login with admin/admin123
- [ ] **CRITICAL**: Changed admin password
- [ ] Generated password hash and added to .env
- [ ] Tested new admin login

### SMTP/Email

- [ ] Email settings configured in .env
- [ ] Test email sends successfully:
  ```bash
  docker-compose exec web python -c "from email_service import send_email; print(send_email('your@email.com', 'Test', '<p>Test</p>'))"
  ```
- [ ] Received test email

## Phase 3: Network Configuration

### FreeRADIUS

- [ ] CoA server configuration created: `freeradius/raddb/sites-available/coa`
- [ ] CoA site enabled: `freeradius/raddb/sites-enabled/coa` symlink exists
- [ ] Portal added to clients.conf with CoA enabled
- [ ] RADIUS secret matches in both FreeRADIUS and portal
- [ ] FreeRADIUS restarted: `docker-compose restart`
- [ ] CoA port listening: `netstat -uln | grep 3799`
- [ ] FreeRADIUS logs show: "Listening on coa address * port 3799"

### HP5130 Switch

Your switch is already configured, verify:
- [ ] MAC authentication enabled globally
- [ ] Ports 19, 21 have MAC auth enabled
- [ ] VLAN 99 configured and accessible
- [ ] All VLANs (10, 20, 30, 40, 50, 60, 70, 90, 99) configured
- [ ] RADIUS server points to 192.168.99.4
- [ ] RADIUS secret matches

### Nginx Proxy Manager

- [ ] NPM accessible at http://192.168.99.4:81
- [ ] Created proxy host for captive portal:
  - Domain or IP configured
  - Forward to 192.168.99.4:8080
  - SSL enabled (if using domain)
- [ ] (Optional) Proxy hosts for captive portal detection:
  - captiveportal.apple.com
  - connectivitycheck.gstatic.com
  - www.msftconnecttest.com

### DNS (Optional)

- [ ] DNS records created for portal domain
- [ ] (Optional) DNS redirects for captive portal detection

### Firewall

- [ ] Port 8080 accessible from VLAN 99
- [ ] Port 3799/UDP accessible for RADIUS CoA
- [ ] Port 80/443 accessible (if not using NPM)
- [ ] Outbound SMTP ports open for email

## Phase 4: Testing

### Test 1: Portal Access

- [ ] From device on VLAN 99: `curl http://192.168.99.4:8080`
- [ ] Portal loads in browser
- [ ] Registration form displays correctly
- [ ] Status page loads

### Test 2: Admin Panel

- [ ] Admin login page loads: `/admin/login`
- [ ] Can login with credentials
- [ ] Dashboard loads with all sections
- [ ] Can access "Add New User" form

### Test 3: Pre-Authorized User Flow

- [ ] Created test user in admin panel:
  - Email: test@example.com
  - Status: guests
  - Dates: today to +30 days
- [ ] From test device on VLAN 99:
  - Portal loads
  - Filled form with test@example.com
  - Submitted successfully
  - Saw success message
- [ ] Device moved to VLAN 40 (guests)
- [ ] Device got new IP on VLAN 40
- [ ] Has full internet access
- [ ] Device shows as "active" in admin panel
- [ ] CoA logged in portal: `docker-compose logs web | grep CoA`
- [ ] CoA logged in FreeRADIUS

### Test 4: Unknown User Flow

- [ ] From test device on VLAN 99:
  - Portal loads
  - Filled form with NEW email
  - Submitted successfully
  - Saw "request submitted" message
- [ ] Admin received email notification
- [ ] Email contains correct details
- [ ] Approval link works
- [ ] Approve form loads with request details
- [ ] Approved with status and dates
- [ ] Device immediately moved to correct VLAN
- [ ] Device has full access
- [ ] User appears in admin panel

### Test 5: Email Verification (if enabled)

- [ ] EMAIL_VERIFICATION_REQUIRED=true in .env
- [ ] Restarted services
- [ ] Pre-authorized user registers
- [ ] Verification email received
- [ ] Verification link works
- [ ] Device moves to correct VLAN after verification
- [ ] Tested timeout (device moves to restricted VLAN)

### Test 6: RADIUS CoA

- [ ] Manual CoA test:
  ```bash
  echo "Calling-Station-Id = \"AA-BB-CC-DD-EE-FF\"" | radclient 192.168.99.4:3799 coa testing123
  ```
- [ ] Received CoA-ACK
- [ ] CoA logged in FreeRADIUS

## Phase 5: Security Hardening

### Passwords & Secrets

- [ ] Admin password changed from default
- [ ] DB_PASSWORD is strong (20+ characters)
- [ ] SECRET_KEY is strong (32+ characters)
- [ ] RADIUS_SECRET is strong (not "testing123")
- [ ] SMTP password secured (using app password)
- [ ] All secrets different from each other

### Access Control

- [ ] HTTPS enabled via NPM (if using domain)
- [ ] Admin panel only accessible from secure network
- [ ] Considered VPN access for admin panel
- [ ] Firewall rules restrict unnecessary access

### Monitoring

- [ ] Know how to check logs: `docker-compose logs -f`
- [ ] Know how to check service status: `docker-compose ps`
- [ ] Set up log monitoring (optional)
- [ ] Set up alerting for errors (optional)

## Phase 6: Backup & Recovery

### Database Backup

- [ ] Created backup script: `/home/admin/backup-portal.sh`
- [ ] Made script executable: `chmod +x`
- [ ] Tested manual backup
- [ ] Added to crontab for automated backups
- [ ] Tested restoration from backup
- [ ] Documented backup location

### Configuration Backup

- [ ] Backed up .env file (securely!)
- [ ] Backed up docker-compose.yml
- [ ] Backed up FreeRADIUS configuration
- [ ] Documented all customizations

## Phase 7: Documentation

### User Documentation

- [ ] Created user guide for registration process
- [ ] Documented what users should do if issues occur
- [ ] Shared portal URL with users

### Admin Documentation

- [ ] Documented how to add users
- [ ] Documented how to approve requests
- [ ] Documented troubleshooting steps
- [ ] Documented backup/restore procedures
- [ ] Created contact list for support

### Network Documentation

- [ ] Documented VLAN assignments
- [ ] Documented user status types
- [ ] Updated network diagram
- [ ] Documented portal architecture

## Phase 8: Production Readiness

### Performance

- [ ] Tested with multiple simultaneous registrations
- [ ] Database performance acceptable
- [ ] Portal response time acceptable
- [ ] No memory leaks or resource issues

### Error Handling

- [ ] Tested with invalid inputs
- [ ] Error messages are user-friendly
- [ ] Errors logged appropriately
- [ ] No sensitive data in error messages

### Monitoring & Alerting

- [ ] Monitoring solution in place (optional)
- [ ] Alerting configured (optional)
- [ ] Log rotation configured
- [ ] Disk space monitoring

## Go-Live Checklist

### Before Launch

- [ ] All above sections completed
- [ ] Stakeholders notified
- [ ] Support team trained
- [ ] Emergency contact information documented
- [ ] Rollback plan prepared

### Launch Day

- [ ] Services running and healthy
- [ ] Monitoring active
- [ ] Support team available
- [ ] Communication sent to users
- [ ] Ready to handle support requests

### Post-Launch (First Week)

- [ ] Monitor logs daily
- [ ] Track registration success rate
- [ ] Collect user feedback
- [ ] Address any issues quickly
- [ ] Document lessons learned

## Maintenance Schedule

### Daily

- [ ] Check service status: `docker-compose ps`
- [ ] Review logs for errors
- [ ] Monitor disk space

### Weekly

- [ ] Review pending registration requests
- [ ] Check database size
- [ ] Review backup success
- [ ] Update documentation

### Monthly

- [ ] Review user access (expire old accounts)
- [ ] Update software (Docker images)
- [ ] Security review
- [ ] Performance review

## Emergency Contacts

Document your contacts:

- Network Administrator: _______________
- System Administrator: _______________
- RADIUS Admin: _______________
- Email Admin: _______________
- On-Call Support: _______________

## Troubleshooting Quick Reference

### Portal not accessible
```bash
docker-compose ps
docker-compose logs web
curl http://localhost:8080/health
docker-compose restart
```

### CoA not working
```bash
docker-compose logs web | grep -i coa
docker-compose -f ../freeradius/docker-compose.yml logs | grep -i coa
netstat -uln | grep 3799
```

### Email not sending
```bash
docker-compose logs web | grep -i email
# Test SMTP in .env
docker-compose restart
```

### Database issues
```bash
docker-compose logs db
docker-compose exec db psql -U portal_user -d captive_portal
```

## Notes

Use this space to document your specific configuration:

- Portal URL: _______________
- Admin email: _______________
- Special configurations: _______________
- Known issues: _______________

---

**Date Deployed**: _______________
**Deployed By**: _______________
**Sign-off**: _______________
