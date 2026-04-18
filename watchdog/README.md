# bf-network Watchdog Daemon

Docker service that monitors sibling containers, the captive-portal health
endpoint, host disk and memory, then emails the admin via Microsoft Graph
when anything goes wrong or recovers.

It starts and restarts automatically with the rest of the stack.  It talks to
Docker via the Engine Unix-socket API — no `docker` CLI binary is needed inside
the container.

> **Note on Docker-daemon crashes**: if Docker itself dies, this container dies
> with it.  In practice this is very rare.  The script also works as a bare
> systemd service for extra resilience — when `/var/run/docker.sock` exists it
> uses the socket API, otherwise it falls back to `docker inspect` subprocess.

---

## What it monitors

| Check | How |
|---|---|
| Docker containers | Docker Engine socket API — alerts on non-running status or unexpected restarts |
| Captive-portal health | `GET /health` — alerts on HTTP error or `status=unhealthy` (includes thread death) |
| Disk usage (host) | `shutil.disk_usage('/hostfs')` via host `/` mount — alert when ≥ threshold |
| Memory usage | `/proc/meminfo` — alert when used ≥ threshold |
| Peer Pi (optional) | `GET peer_health_url` or ping — alerts if unreachable for N consecutive checks |

**Containers monitored by default:**
`captive-portal-db`, `captive-portal-redis`, `captive-portal-web`, `nat-parser`,
`dns-parser`, `portal-tunnel`, `freeradius`, `pihole`, `dnsmasq-hijack`,
`syslog-ng`, `kea`

---

## Deployment

The watchdog is already wired into `docker-compose.yml`.  It starts
automatically with the rest of the stack:

```bash
docker compose up -d              # whole stack — watchdog included
docker compose logs -f watchdog   # watch logs
```

To rebuild after code changes:

```bash
docker compose build watchdog && docker compose up -d watchdog
```

---

## Configuration

Add any of the following to `.env` to override defaults:

| Variable | Default | Description |
|---|---|---|
| `WATCHDOG_INTERVAL_SEC` | `60` | Seconds between each full check cycle |
| `WATCHDOG_HEALTH_URL` | `http://127.0.0.1:8080/health` | Captive-portal health endpoint |
| `WATCHDOG_HEALTH_TIMEOUT_SEC` | `10` | HTTP timeout for health requests |
| `WATCHDOG_HEALTH_FAIL_THRESHOLD` | `3` | Consecutive failures before sending alert |
| `WATCHDOG_DISK_THRESHOLD_PCT` | `85` | Alert when disk used ≥ this % |
| `WATCHDOG_DISK_RECOVER_PCT` | `80` | Recover when disk used ≤ this % |
| `WATCHDOG_MEM_THRESHOLD_PCT` | `90` | Alert when memory used ≥ this % |
| `WATCHDOG_MEM_RECOVER_PCT` | `85` | Recover when memory used ≤ this % |
| `WATCHDOG_CONTAINERS` | (all 11 above) | Comma-separated list of containers to watch |
| `WATCHDOG_SITE_NAME` | derived from `PORTAL_URL` | Label used in email subjects |

### Peer node monitoring (Phase 2)

```ini
# .env additions
WATCHDOG_PEER_HOST=192.168.99.x                        # IP/hostname of peer Pi
WATCHDOG_PEER_HEALTH_URL=http://192.168.99.x:8080/health  # optional health URL
WATCHDOG_PEER_SSH_USER=admin
WATCHDOG_PEER_FAIL_THRESHOLD=3
WATCHDOG_PEER_REBOOT_ENABLED=false   # set true to SSH-reboot the peer
```

The SSH key used is `/home/admin/.ssh/id_rsa` (mounted as `/keys/id_rsa`).

---

## Alert debouncing

- **Containers:** one email on failure, one on recovery; tracks restart count
- **Health / Peer:** emails only after N consecutive failures
- **Disk / Memory:** emails on threshold crossing; won't re-alert until recovered
- **State** persisted to `watchdog/state.json` — survives watchdog restarts

---

## /health endpoint

`app.py` was updated so `/health` now returns thread liveness:

```json
{
  "status": "healthy",
  "db": "ok",
  "threads": {
    "wifi-confirm-sweep": "ok",
    "ip-lease-sweep": "ok",
    "central-outbound": "ok"
  }
}
```

Returns HTTP 500 if DB fails or any tracked thread is dead.
