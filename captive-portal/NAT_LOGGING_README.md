# NAT Logging System

Comprehensive NAT session tracking for UDM Pro with PostgreSQL storage and automatic recovery.

## Architecture

```
UDM (192.168.1.1)
  └─→ conntrack events
      └─→ rsyslog @ 192.168.99.4:514
          └─→ remote-syslog.log
              └─→ nat-parser container
                  └─→ PostgreSQL (captive_portal db)
```

## Features

- **UDM Logger**: Monitors conntrack for SNAT events from VLANs 192.168.1-95
- **Session Grouping**: Combines log entries < 60s apart into single sessions
- **Auto-Recovery**: Reinstalls UDM logger if logs stop for 1 hour
- **Persistence**: UDM logger survives reboots and firmware upgrades
- **Centralized Storage**: Sessions stored in same database as captive portal

## Prerequisites

1. **SSH Key for UDM**
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/udm_key -N ''
   ssh-copy-id -i ~/.ssh/udm_key root@192.168.1.1
   ```

2. **Syslog Container Running**
   - Filter configured for NAT-Logger entries only
   - Located at `/home/admin/bf-network/syslog-container/logs/remote-syslog.log`

3. **Captive Portal Database**
   - PostgreSQL container running
   - NAT sessions schema auto-deployed via `init-db.sql`

## Installation

### 1. Deploy UDM Logger

```bash
# Copy installation script to UDM
scp -i ~/.ssh/udm_key /home/admin/bf-network/scripts/udm-nat-logger-persist.sh \
    root@192.168.1.1:/tmp/

# Execute on UDM (installs to /mnt/data with boot persistence)
ssh -i ~/.ssh/udm_key root@192.168.1.1 \
    "bash /tmp/udm-nat-logger-persist.sh"
```

**What this does:**
- Creates `/mnt/data/nat_logger.sh` (conntrack monitor)
- Creates `/mnt/data/on_boot.d/20-nat-logger.sh` (auto-start on boot)
- Configures rsyslog to forward NAT-Logger entries to Pi
- Starts logger immediately
- **Survives**: Reboots ✓, Firmware upgrades ✓

### 2. Start NAT Parser Container

```bash
cd /home/admin/bf-network/captive-portal

# Build and start all services (including nat-parser)
docker compose up -d --build

# Or just start nat-parser if other services already running
docker compose up -d --build nat-parser
```

**What this does:**
- Builds Python container with psycopg2
- Starts parser monitoring `/logs/remote-syslog.log`
- Connects to PostgreSQL database
- Groups sessions and writes to `nat_sessions` table

## Verification

### Check UDM Logger

```bash
# Check if running
ssh -i ~/.ssh/udm_key root@192.168.1.1 "ps aux | grep nat_logger"

# View logs on UDM
ssh -i ~/.ssh/udm_key root@192.168.1.1 \
    "tail -f /var/log/messages | grep NAT-Logger"
```

### Check Parser Container

```bash
# View container logs
docker logs -f nat-parser

# Check container status
docker ps | grep nat-parser
```

### Check Database

```bash
# Connect to database
docker exec -it captive-portal-db psql -U portal_user -d captive_portal

# View active sessions (last 2 minutes)
SELECT * FROM nat_active_sessions;

# View recent sessions
SELECT * FROM nat_sessions ORDER BY session_end DESC LIMIT 10;

# Stats by source IP
SELECT * FROM nat_session_stats_by_ip LIMIT 20;

# Example: Find all sessions for specific IP
SELECT 
    src_ip, src_port, dst_ip, dst_port,
    session_start, session_end,
    EXTRACT(EPOCH FROM (session_end - session_start)) AS duration_sec,
    packet_count
FROM nat_sessions
WHERE src_ip = '192.168.10.13'
ORDER BY session_start DESC
LIMIT 10;
```

## Database Schema

**Table: `nat_sessions`**
```sql
- id (SERIAL PRIMARY KEY)
- src_ip (INET) - Source IP from internal network
- src_port (INTEGER) - Source port from internal network
- dst_ip (INET) - Destination IP
- dst_port (INTEGER) - Destination port
- protocol (VARCHAR) - tcp/udp
- session_start (TIMESTAMP) - First packet time
- session_end (TIMESTAMP) - Last packet time (within 60s gap)
- packet_count (INTEGER) - Number of log entries in session
- created_at, updated_at (TIMESTAMP)
```

**Views:**
- `nat_active_sessions` - Sessions active in last 2 minutes
- `nat_session_stats_by_ip` - Aggregated stats per source IP

## Session Grouping Example

**Raw Log Entries:**
```
2026-02-15T23:06:25 - 192.168.10.13:46766 → 8.8.8.8:53
2026-02-15T23:06:35 - 192.168.10.13:46766 → 8.8.8.8:53  (10s gap)
2026-02-15T23:06:55 - 192.168.10.13:46766 → 8.8.8.8:53  (20s gap)
2026-02-15T23:07:28 - 192.168.10.13:46766 → 8.8.8.8:53  (33s gap - NEW SESSION)
2026-02-15T23:07:45 - 192.168.10.13:46766 → 8.8.8.8:53  (17s gap)
```

**Database Result:**
```
Session 1: start=23:06:25, end=23:06:55, duration=30s, packets=3
Session 2: start=23:07:28, end=23:07:45, duration=17s, packets=2
```

## Auto-Recovery

If no NAT logs are received for 1 hour, the parser will:
1. Wait 1 hour since last log entry
2. Attempt SSH to UDM at `192.168.1.1`
3. Copy `/config/udm-nat-logger-persist.sh` to UDM
4. Execute installation script
5. Wait 5 minutes before next attempt (if failed)
6. Log all attempts to container logs

**Requirements for auto-recovery:**
- `/home/admin/.ssh/udm_key` mounted to container
- UDM must be reachable via SSH
- If UDM unreachable, logs error but continues monitoring

## Configuration

Environment variables in `docker-compose.yml`:

```yaml
UDM_HOST: 192.168.1.1                    # UDM IP address
SESSION_GAP_SECONDS: 60                  # Max gap to group into same session
STALE_LOG_THRESHOLD_SECONDS: 3600        # 1 hour - trigger reinstall
CHECK_INTERVAL_SECONDS: 5                # How often to check log file
REINSTALL_COOLDOWN_SECONDS: 300          # 5 min between reinstall attempts
```

## Troubleshooting

### No logs appearing in database

1. Check UDM logger is running:
   ```bash
   ssh -i ~/.ssh/udm_key root@192.168.1.1 "ps aux | grep nat_logger"
   ```

2. Check UDM is logging:
   ```bash
   ssh -i ~/.ssh/udm_key root@192.168.1.1 "logread | grep NAT-Logger"
   ```

3. Check syslog container receiving logs:
   ```bash
   tail -f /home/admin/bf-network/syslog-container/logs/remote-syslog.log
   ```

4. Check parser container logs:
   ```bash
   docker logs nat-parser
   ```

### Parser container failing

```bash
# Check logs for errors
docker logs nat-parser

# Check database connectivity
docker exec nat-parser python3 -c "import psycopg2; print('OK')"

# Restart parser
docker compose restart nat-parser
```

### UDM logger not persisting after reboot

```bash
# Check on_boot.d script exists
ssh -i ~/.ssh/udm_key root@192.168.1.1 "ls -la /mnt/data/on_boot.d/"

# Check script is executable
ssh -i ~/.ssh/udm_key root@192.168.1.1 "chmod +x /mnt/data/on_boot.d/20-nat-logger.sh"

# Manually run boot script
ssh -i ~/.ssh/udm_key root@192.168.1.1 "/mnt/data/on_boot.d/20-nat-logger.sh"
```

## Manual UDM Logger Control

```bash
# Stop logger
ssh -i ~/.ssh/udm_key root@192.168.1.1 "kill \$(cat /var/run/nat_logger.pid)"

# Start logger
ssh -i ~/.ssh/udm_key root@192.168.1.1 "/mnt/data/on_boot.d/20-nat-logger.sh"

# Check status
ssh -i ~/.ssh/udm_key root@192.168.1.1 "ps aux | grep nat_logger | grep -v grep"
```

## Log Rotation

The parser handles log rotation automatically:
- Monitors file size
- Resets read position when file shrinks
- No configuration needed

## Performance

- **UDM**: Minimal CPU impact - only logs NEW/ESTABLISHED conntrack events
- **Parser**: Checks log every 5 seconds, processes new lines only
- **Database**: Indexed for fast queries on src_ip, time range, active sessions
- **Storage**: ~100 bytes per session, compress old data as needed

## Uninstalling

### Remove from UDM
```bash
ssh -i ~/.ssh/udm_key root@192.168.1.1 "kill \$(cat /var/run/nat_logger.pid); \
    rm /mnt/data/nat_logger.sh /mnt/data/on_boot.d/20-nat-logger.sh; \
    rm /etc/rsyslog.d/50-nat-logger.conf; \
    systemctl restart rsyslog"
```

### Remove parser container
```bash
cd /home/admin/bf-network/captive-portal
docker compose stop nat-parser
docker compose rm -f nat-parser
```

### Remove database table (optional)
```bash
docker exec -it captive-portal-db psql -U portal_user -d captive_portal \
    -c "DROP TABLE IF EXISTS nat_sessions CASCADE;"
```
