#!/usr/bin/env python3
"""
bf-network Watchdog Daemon
==========================
Monitors Docker containers, the captive-portal health endpoint, disk and
memory on the local node (and optionally a peer Pi), then emails the admin
via Microsoft Graph API when things go wrong or recover.

Deployment: Docker container (see docker-compose.yml watchdog service).  The
container mounts /var/run/docker.sock (read-only) and inspects sibling
containers via the Docker Engine Unix-socket API — no docker CLI needed.
For host disk usage the host root is mounted at /hostfs (read-only).

Config is provided via docker-compose environment variables.  As a fallback
(e.g. bare-metal / systemd install) it also reads the project .env file;
set BF_ENV_FILE to override the path.
"""

import http.client
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [watchdog] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger('watchdog')

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Default .env path: one directory up from this script (i.e. bf-network/.env)
_DEFAULT_ENV = Path(__file__).resolve().parent.parent / '.env'


def _load_env(path: Path) -> dict:
    """Parse a simple KEY=value .env file.  Ignores comments and blanks."""
    env = {}
    if not path.exists():
        log.warning('No .env file found at %s', path)
        return env
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, _, val = line.partition('=')
            env[key.strip()] = val.strip()
    return env


def _cfg(env: dict, key: str, default: str = '') -> str:
    # CLI env overrides .env file
    return os.environ.get(key) or env.get(key) or default


def load_config() -> dict:
    env_path = Path(os.environ.get('BF_ENV_FILE', str(_DEFAULT_ENV)))
    env = _load_env(env_path)

    cfg = {
        # Graph / email
        'graph_tenant_id':    _cfg(env, 'GRAPH_TENANT_ID'),
        'graph_client_id':    _cfg(env, 'GRAPH_CLIENT_ID'),
        'graph_client_secret': _cfg(env, 'GRAPH_CLIENT_SECRET'),
        'graph_from_email':   _cfg(env, 'GRAPH_FROM_EMAIL'),
        'admin_email':        _cfg(env, 'ADMIN_EMAIL'),

        # Site identity (used in email subjects)
        'site_name':          _cfg(env, 'WATCHDOG_SITE_NAME',
                                   _cfg(env, 'PORTAL_URL', 'bf-network').split('/')[-1]),

        # Health endpoint
        'health_url':         _cfg(env, 'WATCHDOG_HEALTH_URL', 'http://127.0.0.1:8080/health'),
        'health_enabled':     _cfg(env, 'WATCHDOG_HEALTH_ENABLED', 'true').lower() != 'false',
        'health_timeout':     int(_cfg(env, 'WATCHDOG_HEALTH_TIMEOUT_SEC', '10')),
        'health_fail_threshold': int(_cfg(env, 'WATCHDOG_HEALTH_FAIL_THRESHOLD', '3')),

        # Polling
        'interval':           int(_cfg(env, 'WATCHDOG_INTERVAL_SEC', '60')),

        # Thresholds
        'disk_threshold_pct': int(_cfg(env, 'WATCHDOG_DISK_THRESHOLD_PCT', '85')),
        'disk_recover_pct':   int(_cfg(env, 'WATCHDOG_DISK_RECOVER_PCT', '80')),
        'mem_threshold_pct':  int(_cfg(env, 'WATCHDOG_MEM_THRESHOLD_PCT', '90')),
        'mem_recover_pct':    int(_cfg(env, 'WATCHDOG_MEM_RECOVER_PCT', '85')),

        # Containers to monitor (comma-separated, or default list)
        'containers':         _parse_containers(_cfg(env, 'WATCHDOG_CONTAINERS')),

        # Peer node (optional)
        'peer_host':          _cfg(env, 'WATCHDOG_PEER_HOST'),
        'peer_health_url':    _cfg(env, 'WATCHDOG_PEER_HEALTH_URL'),
        'peer_ssh_user':      _cfg(env, 'WATCHDOG_PEER_SSH_USER', 'admin'),
        'peer_ssh_key':       _cfg(env, 'WATCHDOG_PEER_SSH_KEY', '/home/admin/.ssh/id_rsa'),
        'peer_fail_threshold': int(_cfg(env, 'WATCHDOG_PEER_FAIL_THRESHOLD', '3')),
        'peer_reboot':        _cfg(env, 'WATCHDOG_PEER_REBOOT_ENABLED', 'false').lower() == 'true',

        # Host filesystem root for disk-usage check.
        # When running in Docker, mount /:/hostfs:ro and set this to /hostfs.
        # Default '/' works for bare-metal / systemd installs.
        'disk_path':          _cfg(env, 'WATCHDOG_DISK_PATH', '/'),

        # Docker socket path (override for non-standard setups)
        'docker_socket':      _cfg(env, 'DOCKER_SOCKET', '/var/run/docker.sock'),

        # State file
        'state_file':         Path(_cfg(env, 'WATCHDOG_STATE_FILE',
                                        str(Path(__file__).parent / 'state.json'))),

        # Central API connectivity check (optional — skipped if URL not set)
        'central_url':        _cfg(env, 'CENTRAL_API_URL'),
        'central_fail_threshold': int(_cfg(env, 'WATCHDOG_CENTRAL_FAIL_THRESHOLD', '3')),
        'central_timeout':    int(_cfg(env, 'WATCHDOG_CENTRAL_TIMEOUT_SEC', '10')),

        # Syslog staleness check — alert if remote-syslog.log hasn't grown for this many seconds
        'syslog_log_path':    _cfg(env, 'WATCHDOG_SYSLOG_LOG_PATH', '/logs/remote-syslog.log'),
        'syslog_stale_sec':   int(_cfg(env, 'WATCHDOG_SYSLOG_STALE_SEC', '600')),
    }
    return cfg


_DEFAULT_CONTAINERS = [
    'captive-portal-db',
    'captive-portal-redis',
    'captive-portal-web',
    'nat-parser',
    'dns-parser',
    'portal-tunnel',
    'freeradius',
    'pihole',
    'dnsmasq-hijack',
    'syslog-ng',
    'kea',
]


def _parse_containers(val: str) -> list:
    if val:
        return [c.strip() for c in val.split(',') if c.strip()]
    return list(_DEFAULT_CONTAINERS)


# ---------------------------------------------------------------------------
# Email via Microsoft Graph (pure stdlib + urllib, no msal dependency)
# ---------------------------------------------------------------------------

_graph_token_cache: dict = {'token': None, 'expires': 0}


def _get_graph_token(cfg: dict) -> str | None:
    now = time.time()
    if _graph_token_cache['token'] and _graph_token_cache['expires'] > now + 60:
        return _graph_token_cache['token']

    tid = cfg['graph_tenant_id']
    cid = cfg['graph_client_id']
    secret = cfg['graph_client_secret']
    if not all([tid, cid, secret]):
        log.warning('Graph API credentials not configured — emails disabled')
        return None

    url = f'https://login.microsoftonline.com/{tid}/oauth2/v2.0/token'
    data = urllib.parse.urlencode({
        'client_id': cid,
        'client_secret': secret,
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials',
    }).encode()

    try:
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
        token = body.get('access_token')
        expires_in = int(body.get('expires_in', 3600))
        _graph_token_cache['token'] = token
        _graph_token_cache['expires'] = now + expires_in
        return token
    except Exception as exc:
        log.error('Failed to obtain Graph token: %s', exc)
        return None


def send_email(cfg: dict, subject: str, html_body: str) -> bool:
    from_email = cfg['graph_from_email']
    to_email = cfg['admin_email']
    if not from_email or not to_email:
        log.warning('Email not configured (GRAPH_FROM_EMAIL or ADMIN_EMAIL missing)')
        return False

    token = _get_graph_token(cfg)
    if not token:
        return False

    payload = {
        'message': {
            'subject': subject,
            'body': {'contentType': 'HTML', 'content': html_body},
            'toRecipients': [{'emailAddress': {'address': to_email}}],
        },
        'saveToSentItems': 'true',
    }

    url = f'https://graph.microsoft.com/v1.0/users/{from_email}/sendMail'
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Content-Type', 'application/json')

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status == 202:
                log.info('Email sent: %s → %s', subject, to_email)
                return True
            log.error('Graph sendMail returned %s', resp.status)
            return False
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors='replace')
        log.error('Graph sendMail HTTP %s: %s', exc.code, body)
        # Token may have expired — clear cache so next call refreshes
        _graph_token_cache['token'] = None
        return False
    except Exception as exc:
        log.error('Graph sendMail failed: %s', exc)
        return False


def _hint(*lines: str) -> str:
    """Return an HTML suggestion block to append to an alert message."""
    inner = '<br>'.join(f'&nbsp;&nbsp;{l}' for l in lines)
    return f'<br><small style="color:#555">&#8627; {inner}</small>'


def _system_stats_html(cfg: dict) -> str:
    """HTML block with current memory and disk usage — included in every alert."""
    lines = []

    # Memory (reads /proc/meminfo — works on host-networked containers)
    mem = _read_meminfo()
    if mem:
        total = mem.get('MemTotal', 0)
        available = mem.get('MemAvailable', 0)
        if total:
            used_pct = (total - available) * 100 // total
            used_mb = (total - available) // 1024
            total_mb = total // 1024
            bar = '&#9608;' * (used_pct // 10) + '&#9617;' * (10 - used_pct // 10)
            lines.append(f'Memory: <strong>{used_pct}%</strong> used '
                         f'({used_mb} MB / {total_mb} MB) {bar}')

    # Disk (uses WATCHDOG_DISK_PATH — /hostfs in Docker, / bare-metal)
    disk_path = cfg.get('disk_path', '/')
    try:
        usage = shutil.disk_usage(disk_path)
        used_pct = usage.used * 100 // usage.total
        free_gb = usage.free / (1024 ** 3)
        total_gb = usage.total / (1024 ** 3)
        bar = '&#9608;' * (used_pct // 10) + '&#9617;' * (10 - used_pct // 10)
        lines.append(f'Disk: <strong>{used_pct}%</strong> used '
                     f'({total_gb - free_gb:.1f} GB / {total_gb:.1f} GB, '
                     f'{free_gb:.1f} GB free) {bar}')
    except Exception:
        pass

    if not lines:
        return ''

    items = ''.join(f'<li>{l}</li>' for l in lines)
    return (
        '<hr style="margin-top:16px">'
        '<p style="color:#555;font-size:0.9em;margin-bottom:4px">'
        '<strong>System stats at time of alert:</strong></p>'
        f'<ul style="font-size:0.9em;margin-top:0">{items}</ul>'
        '<p style="color:#888;font-size:0.82em">'
        'High memory? Run on Pi: <code>free -h &amp;&amp; ps aux --sort=-%mem | head -15</code><br>'
        'High disk? Run on Pi: <code>df -h /</code> &nbsp;&middot;&nbsp; '
        '<code>docker system prune -f</code> &nbsp;&middot;&nbsp; '
        '<code>du -sh /var/lib/docker/* 2&gt;/dev/null | sort -h</code>'
        '</p>'
    )


def _alert_email(cfg: dict, subject: str, lines: list[str]) -> None:
    site = cfg['site_name']
    full_subject = f'[{site}] {subject}'
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    stats_html = _system_stats_html(cfg)
    html = (
        '<html><body>'
        f'<p><strong>{ts}</strong></p>'
        '<ul>' + ''.join(f'<li style="margin-bottom:6px">{l}</li>' for l in lines) + '</ul>'
        + stats_html +
        '<hr><p style="color:#888;font-size:0.85em">bf-network watchdog</p>'
        '</body></html>'
    )
    send_email(cfg, full_subject, html)


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def _load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(path)


def _container_state(state: dict, name: str) -> dict:
    return state.setdefault('containers', {}).setdefault(name, {
        'restart_count': 0,
        'alerting': False,
    })


def _check_state(state: dict, key: str) -> dict:
    return state.setdefault(key, {'alerting': False, 'consecutive_failures': 0})


# ---------------------------------------------------------------------------
# Docker container checks
# ---------------------------------------------------------------------------

class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects to a Unix domain socket."""
    def __init__(self, socket_path: str) -> None:
        super().__init__('localhost')
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._socket_path)


def inspect_container(name: str, docker_socket: str) -> dict | None:
    """
    Return container State (status, restart_count, exit_code) or None if the
    container does not exist.

    Prefers the Docker Engine Unix-socket API (works inside Docker without a
    docker CLI binary).  Falls back to `docker inspect` subprocess when the
    socket is not available (bare-metal / dev environments).
    """
    if os.path.exists(docker_socket):
        return _inspect_via_socket(name, docker_socket)
    return _inspect_via_subprocess(name)


def _inspect_via_socket(name: str, socket_path: str) -> dict | None:
    try:
        conn = _UnixHTTPConnection(socket_path)
        conn.request('GET', f'/containers/{urllib.parse.quote(name, safe="")}/json')
        resp = conn.getresponse()
        if resp.status == 404:
            return None
        body = json.loads(resp.read())
        return {
            'status': body['State']['Status'],
            'restart_count': body['RestartCount'],
            'exit_code': body['State']['ExitCode'],
        }
    except Exception as exc:
        log.warning('Docker socket inspect %s failed: %s', name, exc)
        return None


def _inspect_via_subprocess(name: str) -> dict | None:
    fmt = '{{.State.Status}}|{{.RestartCount}}|{{.State.ExitCode}}'
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format', fmt, name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        parts = result.stdout.strip().split('|')
        if len(parts) != 3:
            return None
        return {
            'status': parts[0],
            'restart_count': int(parts[1]),
            'exit_code': int(parts[2]),
        }
    except Exception as exc:
        log.warning('docker inspect subprocess %s failed: %s', name, exc)
        return None


def check_containers(cfg: dict, state: dict) -> list[str]:
    """Check all configured containers. Returns list of alert messages."""
    alerts = []
    docker_socket = cfg['docker_socket']
    for name in cfg['containers']:
        info = inspect_container(name, docker_socket)
        cs = _container_state(state, name)

        if info is None:
            # Container not found at all
            if not cs.get('alerting'):
                cs['alerting'] = True
                msg = (
                    f'Container <strong>{name}</strong> not found '
                    f'(may not exist yet or Docker is down)'
                    + _hint(f'Check Docker is running: <code>docker ps</code>',
                            f'Start the stack: <code>docker compose up -d</code>')
                )
                log.warning('Container %s not found', name)
                alerts.append(msg)
            continue

        status = info['status']
        restart_count = info['restart_count']
        prev_restart = cs.get('restart_count', restart_count)

        # Alert if container is not running
        if status != 'running':
            if not cs.get('alerting'):
                cs['alerting'] = True
                msg = (
                    f'Container <strong>{name}</strong> is <strong>{status}</strong> '
                    f'(exit code {info["exit_code"]})'
                    + _hint(
                        f'View logs: <code>docker logs {name} --tail 50</code>',
                        f'Restart: <code>docker compose up -d</code>',
                    )
                )
                log.warning('Container %s is %s (exit %s)', name, status, info['exit_code'])
                alerts.append(msg)
        else:
            # Running — check for unexpected restarts since last poll
            if restart_count > prev_restart:
                restarts = restart_count - prev_restart
                msg = (
                    f'Container <strong>{name}</strong> restarted '
                    f'{"once" if restarts == 1 else f"{restarts} times"} '
                    f'(total restarts: {restart_count})'
                    + _hint(
                        f'View recent logs: <code>docker logs {name} --tail 50</code>',
                        'Repeated restarts may indicate a crash loop — check for errors in the logs',
                    )
                )
                log.warning('Container %s restarted (%d times)', name, restarts)
                alerts.append(msg)
                # Keep alerting=True so we don't send a "recovered" email for restarts
                cs['alerting'] = True
            elif cs.get('alerting'):
                # Container was down but is now running and hasn't restarted again
                cs['alerting'] = False
                msg = f'Container <strong>{name}</strong> has recovered (now running)'
                log.info(msg)
                alerts.append(f'RECOVERED: {msg}')

        cs['restart_count'] = restart_count

    return alerts


# ---------------------------------------------------------------------------
# Health endpoint check
# ---------------------------------------------------------------------------

def check_health(cfg: dict, state: dict) -> list[str]:
    """Poll the captive-portal /health endpoint."""
    if not cfg.get('health_enabled', True):
        return []
    url = cfg['health_url']
    timeout = cfg['health_timeout']
    threshold = cfg['health_fail_threshold']
    hs = _check_state(state, 'health')
    alerts = []

    ok = False
    detail = ''
    suggestion_lines = []
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
            ok = (resp.status == 200 and body.get('status') == 'healthy')
            if not ok:
                # Server responded but reports unhealthy — extract specifics
                parts = []
                db_s = body.get('db', '')
                if db_s and db_s != 'ok':
                    parts.append(f'database error: {db_s}')
                    suggestion_lines = [
                        'Check DB container: <code>docker logs captive-portal-db --tail 50</code>',
                        'Restart DB if needed: <code>docker compose up -d db</code>',
                    ]
                threads = body.get('threads', {})
                dead = [t for t, s in threads.items() if s == 'dead']
                if dead:
                    parts.append(f'dead background thread(s): {", ".join(dead)}')
                    suggestion_lines = [
                        'Restart the captive portal: <code>docker compose up -d web</code>',
                        'Check for errors: <code>docker logs captive-portal-web --tail 100</code>',
                        'If it recurs the thread is crash-looping — check logs carefully',
                    ]
                detail = '; '.join(parts) or 'status reported unhealthy'
    except urllib.error.HTTPError as exc:
        # Server is reachable and returned HTTP 500 — try to parse the health body
        try:
            body = json.loads(exc.read())
            parts = []
            db_s = body.get('db', '')
            if db_s and db_s != 'ok':
                parts.append(f'database error: {db_s}')
                suggestion_lines = [
                    'Check DB container: <code>docker logs captive-portal-db --tail 50</code>',
                    'Restart DB if needed: <code>docker compose up -d db</code>',
                ]
            threads = body.get('threads', {})
            dead = [t for t, s in threads.items() if s == 'dead']
            if dead:
                parts.append(f'dead background thread(s): {", ".join(dead)}')
                suggestion_lines = [
                    'Restart the captive portal: <code>docker compose up -d web</code>',
                    'Check for errors: <code>docker logs captive-portal-web --tail 100</code>',
                    'If it recurs the thread is crash-looping — check logs carefully',
                ]
            detail = '; '.join(parts) or f'HTTP {exc.code}'
        except Exception:
            detail = f'HTTP {exc.code} ({exc.reason})'
            suggestion_lines = [
                'Check container logs: <code>docker logs captive-portal-web --tail 100</code>',
                'Restart if needed: <code>docker compose up -d web</code>',
            ]
    except urllib.error.URLError as exc:
        # Genuine connection failure — server not reachable at all
        detail = f'captive portal unreachable ({exc.reason})'
        suggestion_lines = [
            'Check it is running: <code>docker ps | grep web</code>',
            'Restart: <code>docker compose up -d web</code>',
            'View startup errors: <code>docker logs captive-portal-web --tail 100</code>',
        ]
    except Exception as exc:
        detail = str(exc)
        suggestion_lines = ['Restart captive portal: <code>docker compose up -d web</code>']

    if not ok:
        hs['consecutive_failures'] = hs.get('consecutive_failures', 0) + 1
        cf = hs['consecutive_failures']
        log.warning('Health check failed (%d/%d): %s', cf, threshold, detail)
        if cf >= threshold and not hs.get('alerting'):
            hs['alerting'] = True
            msg = (
                f'Captive portal health check failed {cf} times in a row: <strong>{detail}</strong>'
                + (_hint(*suggestion_lines) if suggestion_lines else '')
            )
            alerts.append(msg)
    else:
        if hs.get('alerting'):
            hs['alerting'] = False
            hs['consecutive_failures'] = 0
            msg = 'Health endpoint has recovered'
            log.info(msg)
            alerts.append(f'RECOVERED: {msg}')
        else:
            hs['consecutive_failures'] = 0

    return alerts


# ---------------------------------------------------------------------------
# Disk check
# ---------------------------------------------------------------------------

def check_disk(cfg: dict, state: dict) -> list[str]:
    ds = _check_state(state, 'disk')
    alerts = []
    disk_path = cfg.get('disk_path', '/')
    try:
        usage = shutil.disk_usage(disk_path)
        used_pct = usage.used * 100 // usage.total
        threshold = cfg['disk_threshold_pct']
        recover = cfg['disk_recover_pct']
        free_gb = usage.free / (1024 ** 3)

        if used_pct >= threshold:
            if not ds.get('alerting'):
                ds['alerting'] = True
                msg = (
                    f'Disk usage is <strong>{used_pct}%</strong> '
                    f'(only {free_gb:.1f} GB free) — threshold {threshold}%'
                    + _hint(
                        'Check usage: <code>df -h /</code>',
                        'Find large directories: <code>du -sh /var/lib/docker/* 2&gt;/dev/null | sort -h</code>',
                        'Reclaim Docker space: <code>docker system prune -f</code>',
                        'Check logs directory: <code>du -sh ~/bf-network/*/logs</code>',
                    )
                )
                log.warning('Disk usage %d%% (free %.1f GB)', used_pct, free_gb)
                alerts.append(msg)
        elif ds.get('alerting') and used_pct <= recover:
            ds['alerting'] = False
            msg = f'Disk usage recovered to {used_pct}% ({free_gb:.1f} GB free)'
            log.info(msg)
            alerts.append(f'RECOVERED: {msg}')
    except Exception as exc:
        log.warning('Disk check failed: %s', exc)
    return alerts


# ---------------------------------------------------------------------------
# Memory check
# ---------------------------------------------------------------------------

def _read_meminfo() -> dict:
    info = {}
    try:
        with open('/proc/meminfo') as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(':')] = int(parts[1])  # kB
    except Exception:
        pass
    return info


def check_memory(cfg: dict, state: dict) -> list[str]:
    ms = _check_state(state, 'memory')
    alerts = []
    mem = _read_meminfo()
    if not mem:
        return alerts

    total = mem.get('MemTotal', 0)
    available = mem.get('MemAvailable', 0)
    if total == 0:
        return alerts

    used_pct = (total - available) * 100 // total
    threshold = cfg['mem_threshold_pct']
    recover = cfg['mem_recover_pct']
    avail_mb = available // 1024

    if used_pct >= threshold:
        if not ms.get('alerting'):
            ms['alerting'] = True
            msg = (
                f'Memory usage is <strong>{used_pct}%</strong> '
                f'(only {avail_mb} MB available) — threshold {threshold}%'
                + _hint(
                    'Identify top consumers: <code>ps aux --sort=-%mem | head -15</code>',
                    'Check overall usage: <code>free -h</code>',
                    'Restart all containers: <code>docker compose restart</code>',
                    'If persistent after restart, a process may have a memory leak',
                )
            )
            log.warning('Memory usage %d%% (%d MB available)', used_pct, avail_mb)
            alerts.append(msg)
    elif ms.get('alerting') and used_pct <= recover:
        ms['alerting'] = False
        msg = f'Memory usage recovered to {used_pct}% ({avail_mb} MB available)'
        log.info(msg)
        alerts.append(f'RECOVERED: {msg}')

    return alerts


# ---------------------------------------------------------------------------
# Peer node check (optional)
# ---------------------------------------------------------------------------

def check_peer(cfg: dict, state: dict) -> list[str]:
    peer_host = cfg['peer_host']
    peer_url = cfg['peer_health_url']
    if not peer_host and not peer_url:
        return []

    threshold = cfg['peer_fail_threshold']
    ps = _check_state(state, 'peer')
    alerts = []

    ok = False
    detail = ''

    # Try the health URL if configured, otherwise just ping
    if peer_url:
        try:
            req = urllib.request.Request(peer_url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read())
                ok = (resp.status == 200 and body.get('status') == 'healthy')
                if not ok:
                    detail = f'status={body.get("status", "unknown")}'
        except Exception as exc:
            detail = str(exc)
    elif peer_host:
        result = subprocess.run(
            ['ping', '-c', '2', '-W', '3', peer_host],
            capture_output=True, timeout=10,
        )
        ok = (result.returncode == 0)
        if not ok:
            detail = 'no ping response'

    if not ok:
        ps['consecutive_failures'] = ps.get('consecutive_failures', 0) + 1
        cf = ps['consecutive_failures']
        log.warning('Peer check failed (%d/%d): %s', cf, threshold, detail)
        if cf >= threshold and not ps.get('alerting'):
            ps['alerting'] = True
            host_label = peer_url or peer_host
            alerts.append(
                f'Peer node <strong>{host_label}</strong> is unreachable '
                f'after {cf} checks: {detail}'
            )
            # Optionally reboot the peer via SSH
            if cfg['peer_reboot'] and cfg['peer_host']:
                _try_peer_reboot(cfg)
    else:
        if ps.get('alerting'):
            ps['alerting'] = False
            ps['consecutive_failures'] = 0
            host_label = peer_url or peer_host
            alerts.append(f'RECOVERED: Peer node <strong>{host_label}</strong> is reachable again')
        else:
            ps['consecutive_failures'] = 0

    return alerts


def _try_peer_reboot(cfg: dict) -> None:
    host = cfg['peer_host']
    user = cfg['peer_ssh_user']
    key = cfg['peer_ssh_key']
    log.warning('Attempting SSH reboot of peer %s@%s', user, host)
    try:
        subprocess.run(
            ['ssh', '-i', key, '-o', 'StrictHostKeyChecking=no',
             '-o', 'ConnectTimeout=10', f'{user}@{host}',
             'sudo reboot'],
            capture_output=True, timeout=20,
        )
        log.info('SSH reboot command sent to %s', host)
    except Exception as exc:
        log.error('SSH reboot of %s failed: %s', host, exc)


# ---------------------------------------------------------------------------
# Central API connectivity check
# ---------------------------------------------------------------------------

def check_central(cfg: dict, state: dict) -> list[str]:
    """Check that the local Pi can reach bf-central's /health endpoint."""
    base_url = cfg['central_url'].rstrip('/')
    if not base_url:
        return []

    timeout = cfg['central_timeout']
    threshold = cfg['central_fail_threshold']
    cs = _check_state(state, 'central')
    alerts = []

    ok = False
    detail = ''
    url = f'{base_url}/health'
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
            ok = (resp.status == 200 and body.get('status') == 'ok')
            if not ok:
                detail = f'unexpected response: {body}'
    except urllib.error.HTTPError as exc:
        detail = f'HTTP {exc.code} ({exc.reason})'
    except urllib.error.URLError as exc:
        detail = f'unreachable ({exc.reason})'
    except Exception as exc:
        detail = str(exc)

    if not ok:
        cs['consecutive_failures'] = cs.get('consecutive_failures', 0) + 1
        cf = cs['consecutive_failures']
        log.warning('Central check failed (%d/%d): %s', cf, threshold, detail)
        if cf >= threshold and not cs.get('alerting'):
            cs['alerting'] = True
            alerts.append(
                f'Cannot reach bf-central (<code>{base_url}</code>) '
                f'after {cf} consecutive checks: <strong>{detail}</strong>'
                + _hint(
                    'Check internet/tunnel: <code>curl -s ' + base_url + '/health</code>',
                    'Check the SSH tunnel container: <code>docker logs portal-tunnel --tail 50</code>',
                    'Central sync events are queuing up locally and will replay once restored',
                )
            )
    else:
        if cs.get('alerting'):
            cs['alerting'] = False
            cs['consecutive_failures'] = 0
            alerts.append(f'RECOVERED: Connection to bf-central (<code>{base_url}</code>) restored')
        else:
            cs['consecutive_failures'] = 0

    return alerts


# ---------------------------------------------------------------------------
# Syslog staleness check
# ---------------------------------------------------------------------------

def check_syslog_stale(cfg: dict, state: dict) -> list[str]:
    """Alert if the remote syslog file hasn't been written to recently.

    This catches the case where the NAT logger on the UDM has stopped
    sending data (e.g. wrong SYSLOG_SERVER IP, process died, UDM reboot)
    without requiring the nat-parser container itself to be down.
    """
    log_path = cfg['syslog_log_path']
    stale_sec = cfg['syslog_stale_sec']
    if not log_path:
        return []

    ss = _check_state(state, 'syslog_stale')
    alerts = []

    try:
        mtime = os.path.getmtime(log_path)
        age = time.time() - mtime
        if age > stale_sec:
            if not ss.get('alerting'):
                ss['alerting'] = True
                minutes = int(age // 60)
                alerts.append(
                    f'Remote syslog file <code>{log_path}</code> has not been updated '
                    f'for <strong>{minutes} minutes</strong> — '
                    f'the NAT logger on the UDM may have stopped.'
                    + _hint(
                        'Check NAT logger: <code>ssh root@192.168.1.1 pgrep -af nat_logger</code>',
                        'Reinstall: <code>docker restart nat-parser</code> (auto-reinstalls if down)',
                    )
                )
                log.warning('Syslog stale: %s not updated for %ds', log_path, int(age))
        else:
            if ss.get('alerting'):
                ss['alerting'] = False
                alerts.append(
                    f'RECOVERED: Remote syslog file <code>{log_path}</code> is receiving data again'
                )
            ss['consecutive_failures'] = 0
    except FileNotFoundError:
        if not ss.get('alerting'):
            ss['alerting'] = True
            alerts.append(
                f'Remote syslog file <code>{log_path}</code> not found — '
                f'syslog-ng may not be running or the volume is not mounted.'
                + _hint('Check: <code>docker logs syslog-ng</code>')
            )
            log.warning('Syslog file not found: %s', log_path)
    except Exception as exc:
        log.warning('Syslog stale check failed: %s', exc)

    return alerts


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _categorise(alerts: list[str]) -> tuple[list[str], list[str]]:
    problems = [a for a in alerts if not a.startswith('RECOVERED:')]
    recoveries = [a.removeprefix('RECOVERED: ') for a in alerts if a.startswith('RECOVERED:')]
    return problems, recoveries


def run_once(cfg: dict, state: dict) -> None:
    all_alerts: list[str] = []
    all_alerts += check_containers(cfg, state)
    all_alerts += check_health(cfg, state)
    all_alerts += check_disk(cfg, state)
    all_alerts += check_memory(cfg, state)
    all_alerts += check_peer(cfg, state)
    all_alerts += check_central(cfg, state)
    all_alerts += check_syslog_stale(cfg, state)

    problems, recoveries = _categorise(all_alerts)

    if problems:
        _alert_email(cfg, f'ALERT — {len(problems)} issue(s) detected', problems)

    if recoveries:
        _alert_email(cfg, f'RECOVERED — {len(recoveries)} issue(s) resolved', recoveries)


def main() -> None:
    cfg = load_config()
    state_path = cfg['state_file']

    log.info('bf-network watchdog starting (interval=%ds site=%s)',
             cfg['interval'], cfg['site_name'])
    log.info('Monitoring %d containers: %s', len(cfg['containers']),
             ', '.join(cfg['containers']))
    log.info('Health URL: %s', cfg['health_url'])
    if cfg['peer_host'] or cfg['peer_health_url']:
        log.info('Peer monitoring: %s', cfg['peer_health_url'] or cfg['peer_host'])
    else:
        log.info('Peer monitoring: disabled')
    if cfg['central_url']:
        log.info('Central connectivity check: %s/health', cfg['central_url'].rstrip('/'))
    else:
        log.info('Central connectivity check: disabled (CENTRAL_API_URL not set)')
    if not cfg['admin_email']:
        log.warning('ADMIN_EMAIL not set — email alerts disabled')

    state = _load_state(state_path)

    while True:
        try:
            run_once(cfg, state)
        except Exception as exc:
            log.exception('Unexpected error in watchdog loop: %s', exc)
        try:
            _save_state(state_path, state)
        except Exception as exc:
            log.error('Failed to save state: %s', exc)
        time.sleep(cfg['interval'])


if __name__ == '__main__':
    main()
