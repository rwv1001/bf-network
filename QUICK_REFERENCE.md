# Three-Pool WiFi Captive Portal - Quick Reference

## Pool IP Ranges (Per VLAN)

| Pool | IP Range | Lease | DNS | Access | Who |
|------|----------|-------|-----|--------|-----|
| **Registered** | .5 - .127 | 24h | 8.8.8.8 | Full Internet | Approved devices |
| **Newly Unregistered** | .128 - .191 | 60s | 192.168.X.4 | Portal only | First seen <30 min |
| **Old Unregistered** | .192 - .254 | 24h | 192.168.X.4 | Portal only | First seen >30 min |

## Quick Commands

### Check kea-sync Service
```bash
sudo systemctl status kea-sync
sudo journalctl -u kea-sync -f -n 50
```

### Restart Kea DHCP
```bash
cd /home/admin/bf-network/kea
docker compose restart kea-dhcp4
docker compose logs -f kea-dhcp4
```

### Query Device Pool Assignments
```bash
docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml exec db \
  psql -U captive_user -d captive_portal -c \
  "SELECT mac_address, registration_status, first_seen, 
   EXTRACT(EPOCH FROM (NOW() - first_seen)) AS age_seconds 
   FROM devices 
   ORDER BY first_seen DESC LIMIT 10;"
```

### Check Kea Reservations
```bash
cd /home/admin/bf-network/kea
docker compose exec kea-dhcp4 sh -c \
  "echo '{\"command\":\"reservation-get-all\",\"service\":[\"dhcp4\"],\"arguments\":{\"subnet-id\":99}}' | \
   socat - UNIX-CONNECT:/tmp/kea-dhcp4.sock" | jq .
```

### View Active Leases
```bash
cd /home/admin/bf-network/kea
docker compose exec kea-dhcp4 cat /kea/leases/kea-leases4.csv | tail -20
```

### Manually Register Device (via CLI)
```bash
docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml exec db \
  psql -U captive_user -d captive_portal -c \
  "UPDATE devices SET registration_status='approved' WHERE mac_address='aa:bb:cc:dd:ee:ff';"
```

### Manually Add Kea Reservation
```bash
cd /home/admin/bf-network/kea
docker compose exec kea-dhcp4 sh -c \
  "echo '{\"command\":\"reservation-add\",\"service\":[\"dhcp4\"],\"arguments\":{\"reservation\":{\"hw-address\":\"aa:bb:cc:dd:ee:ff\",\"hostname\":\"mydevice\"},\"subnet-id\":99}}' | \
   socat - UNIX-CONNECT:/tmp/kea-dhcp4.sock"
```

### Remove Kea Reservation
```bash
cd /home/admin/bf-network/kea
docker compose exec kea-dhcp4 sh -c \
  "echo '{\"command\":\"reservation-del\",\"service\":[\"dhcp4\"],\"arguments\":{\"subnet-id\":99,\"identifier-type\":\"hw-address\",\"identifier\":\"aa:bb:cc:dd:ee:ff\"}}' | \
   socat - UNIX-CONNECT:/tmp/kea-dhcp4.sock"
```

### Force DHCP Lease Deletion (Immediate Renewal)
```bash
cd /home/admin/bf-network/kea
docker compose exec kea-dhcp4 sh -c \
  "echo '{\"command\":\"lease4-del\",\"service\":[\"dhcp4\"],\"arguments\":{\"ip-address\":\"192.168.99.150\"}}' | \
   socat - UNIX-CONNECT:/tmp/kea-dhcp4.sock"
```

## Troubleshooting

### Device Not Getting Short Lease
1. Check Kea pool configuration
2. Verify device not in reservations already
3. Check Kea logs for errors

### Registration Not Taking Effect
1. Check kea-sync.py running: `systemctl status kea-sync`
2. Verify database `first_seen` column exists
3. Check host reservation created in Kea
4. Force device to renew DHCP (disconnect/reconnect)

### Portal Not Accessible
1. Check web service: `docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml ps`
2. Verify DNS pointing to portal: `nslookup example.com 192.168.99.4`
3. Check firewall allows traffic to .4:8080

### Device Stuck in Unregistered Pool
1. Verify `registration_status='approved'` in database
2. Check kea-sync logs for errors
3. Verify PostgreSQL connection works
4. Manually check Kea reservation exists

## File Locations

| Component | Path |
|-----------|------|
| Kea Config | `/home/admin/bf-network/kea/config/dhcp4-simple-pools.json` |
| kea-sync Script | `/home/admin/bf-network/kea/scripts/kea-sync.py` |
| kea-sync Service | `/etc/systemd/system/kea-sync.service` |
| Kea Leases | `/home/admin/bf-network/kea/leases/kea-leases4.csv` |
| Kea Reservations | `/home/admin/bf-network/kea/data/kea-reservations.json` |
| Control Socket | `/tmp/kea-dhcp4.sock` |
| Flask App | `/home/admin/bf-network/captive-portal/app/app.py` |
| Kea Integration | `/home/admin/bf-network/captive-portal/app/kea_integration.py` |
| Database | PostgreSQL container (captive_portal DB) |

## Environment Variables (kea-sync)

```bash
DB_HOST=127.0.0.1
DB_PORT=5432
POSTGRES_DB=captive_portal
POSTGRES_USER=captive_user
POSTGRES_PASSWORD=<your_password>
KEA_CONTROL_SOCKET=/tmp/kea-dhcp4.sock
SYNC_INTERVAL=60
```

## Important Notes

- **DHCP renewal**: Clients renew at T1 (50% of lease time), so 60s lease = ~30s renewal
- **Pool aging**: Devices automatically age from newly→old unregistered after 30 minutes
- **Sync frequency**: kea-sync runs every 60 seconds by default
- **Database index**: `first_seen` field indexed for performance
- **MAC format**: Kea uses lowercase colon-separated (aa:bb:cc:dd:ee:ff)

## Testing Sequence

1. **New device connects** → Gets .128-.191 IP (60s lease)
2. **Portal accessible** → Can browse to 192.168.X.4:8080/portal
3. **User registers** → Form submission, emails sent
4. **Admin approves** → Database updated, Kea reservation created
5. **Wait 30-60s** → Device renews DHCP
6. **Gets .5-.127 IP** → 24h lease, public DNS
7. **Full internet** → All websites accessible
8. **After 30 min** (unregistered) → Move to .192-.254 (24h lease)
9. **Unregister link** → Removes reservation, back to walled garden

## Performance Metrics

- **Registration to activation**: 30-60 seconds (limited by DHCP renewal)
- **Portal response time**: <500ms
- **kea-sync latency**: <5 seconds
- **DHCP lease acquisition**: <1 second
- **Database query time**: <100ms

## Security Considerations

- ✅ DHCP snooping enabled (prevents IP spoofing)
- ✅ MAC address validation (normalized format)
- ✅ Email verification required
- ✅ Admin approval workflow
- ✅ Unregister tokens (time-limited)
- ✅ Walled garden enforcement (firewall rules)
- ✅ Database indexing (prevents DoS via slow queries)

## Capacity Planning

| Component | Limit | Notes |
|-----------|-------|-------|
| Registered IPs | 123 per VLAN | .5 to .127 = 123 addresses |
| Newly Unregistered | 64 per VLAN | .128 to .191 = 64 addresses |
| Old Unregistered | 63 per VLAN | .192 to .254 = 63 addresses |
| Total per VLAN | 250 devices | Minus 5 reserved (.1-.4) |
| kea-sync capacity | ~1000 devices | 60s sync interval |
| PostgreSQL | Unlimited | With proper indexing |

## Monitoring Checklist

- [ ] kea-sync service running
- [ ] Kea DHCP responding to requests
- [ ] PostgreSQL database accessible
- [ ] Captive portal web service up
- [ ] DNS redirecting properly
- [ ] Firewall rules active
- [ ] Email service working
- [ ] Disk space for lease database
- [ ] Log rotation configured

## Emergency Procedures

### All Devices Lose Internet
1. Check Kea running: `docker compose ps`
2. Check kea-sync: `systemctl status kea-sync`
3. Restart Kea: `docker compose restart kea-dhcp4`
4. Restart kea-sync: `systemctl restart kea-sync`

### Portal Not Loading
1. Check web service: `docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml ps`
2. Check logs: `docker compose logs web`
3. Restart: `docker compose restart web`

### Database Connection Failures
1. Check PostgreSQL: `docker compose ps db`
2. Check credentials in kea-sync service
3. Test connection: `psql -h 127.0.0.1 -U captive_user -d captive_portal`

### Mass Re-registration Needed
```bash
# Approve all pending devices
docker compose -f /home/admin/bf-network/captive-portal/docker-compose.yml exec db \
  psql -U captive_user -d captive_portal -c \
  "UPDATE devices SET registration_status='approved' WHERE registration_status='pending';"

# Wait for kea-sync to process (60 seconds)
# Or restart it: sudo systemctl restart kea-sync
```
