"""
Background sweeper threads.

- WiFi confirmation expiry sweeper
- IP lease expiry sweeper (removes DNS hijacks / ACL blocks for expired leases)
- Heartbeat helpers (shared across gunicorn workers via a file)
- Startup hooks called from create_app()
"""

import json
import logging
import os
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

_HEARTBEAT_FILE = os.getenv('WATCHDOG_HEARTBEAT_FILE', '/tmp/bf-thread-heartbeats.json')
_HEARTBEAT_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Heartbeat helpers
# ---------------------------------------------------------------------------

def heartbeat(thread_name: str) -> None:
    """Write a fresh timestamp for this thread to the shared heartbeat file."""
    try:
        with _HEARTBEAT_LOCK:
            try:
                beats = json.loads(open(_HEARTBEAT_FILE).read())
            except Exception:
                beats = {}
            beats[thread_name] = time.time()
            tmp = _HEARTBEAT_FILE + '.tmp'
            with open(tmp, 'w') as f:
                f.write(json.dumps(beats))
            os.replace(tmp, _HEARTBEAT_FILE)
    except Exception:
        pass


def check_heartbeats(max_stale_sec: int) -> dict:
    """
    Return {thread_name: 'ok'|'dead'|'unknown'} for monitored threads.
    'unknown' means the heartbeat file hasn't been written yet.
    """
    monitored = ['wifi-confirm-sweep', 'ip-lease-sweep', 'central-outbound']
    if not (os.getenv('CENTRAL_API_URL', '').strip() and os.getenv('CENTRAL_API_KEY', '').strip()):
        monitored.remove('central-outbound')

    try:
        beats = json.loads(open(_HEARTBEAT_FILE).read())
    except Exception:
        return {name: 'unknown' for name in monitored}

    now = time.time()
    result = {}
    for name in monitored:
        if name not in beats:
            result[name] = 'unknown'
        elif now - beats[name] > max_stale_sec:
            result[name] = 'dead'
        else:
            result[name] = 'ok'
    return result


# ---------------------------------------------------------------------------
# WiFi confirmation sweeper
# ---------------------------------------------------------------------------

def _sweep_expired_wifi_confirmations(app) -> None:
    """Background thread: unregister devices whose WiFi confirmation has expired."""
    from core.portal_utils import wifi_confirm_sweep_interval_sec

    def _env_truthy(name, default=False):
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {'1', 'true', 'yes', 'on'}

    if not _env_truthy('WIFI_CONFIRM_SWEEP_ENABLED', True):
        return

    interval = wifi_confirm_sweep_interval_sec()
    while True:
        try:
            with app.app_context():
                # db must be imported inside the app context so Flask-SQLAlchemy
                # can resolve the correct app binding for this thread.
                from extensions import db
                from datetime import datetime
                from models import Device
                from core.device_utils import unregister_device

                try:
                    now = datetime.utcnow()
                    expired = Device.query.filter(
                        Device.registration_status == 'registered',
                        Device.confirmation_deadline.isnot(None),
                        Device.confirmation_confirmed_at.is_(None),
                        Device.confirmation_deadline <= now,
                    ).all()
                    for device in expired:
                        logger.info(
                            "WiFi confirmation expired for %s; unregistering device",
                            device.mac_address,
                        )
                        unregister_device(device)
                finally:
                    db.session.remove()
        except Exception as exc:
            logger.warning("WiFi confirmation sweep failed: %s", exc)
        heartbeat('wifi-confirm-sweep')
        time.sleep(interval)


def start_wifi_confirmation_sweeper(app) -> None:
    def _env_truthy(name, default=False):
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {'1', 'true', 'yes', 'on'}

    if not _env_truthy('WIFI_CONFIRM_SWEEP_ENABLED', True):
        return
    thread = threading.Thread(
        target=_sweep_expired_wifi_confirmations,
        args=(app,),
        daemon=True,
        name='wifi-confirm-sweep',
    )
    thread.start()


# ---------------------------------------------------------------------------
# IP lease expiry sweeper
# ---------------------------------------------------------------------------

def _sweep_expired_ip_leases(app) -> None:
    """
    Background thread: clean up DNS hijacks / ACL blocks for expired IPLease rows.
    Also sets internet_accessible=null for MACs with no active leases.
    """
    interval = int(os.getenv('IP_LEASE_SWEEP_INTERVAL', '20'))
    while True:
        try:
            with app.app_context():
                # db must be imported inside the app context so Flask-SQLAlchemy
                # can resolve the correct app binding for this thread.
                from extensions import db
                from datetime import datetime
                from models import IPLease, Device
                from core.network import manage_dns_hijack, manage_switch_acl

                try:
                    now = datetime.utcnow()
                    expired = IPLease.query.filter(IPLease.lease_expiry <= now).all()
                    changed = False
                    for lease in expired:
                        try:
                            if lease.dns_hijacked:
                                manage_dns_hijack('unhijack', lease.ip_address)
                            if lease.vlan_id and not lease.from_blocked_pool:
                                manage_switch_acl('unblock', lease.ip_address, lease.vlan_id)
                            logger.info(
                                "Lease sweep: cleaned up %s (VLAN %s) — lease expired at %s",
                                lease.ip_address, lease.vlan_id, lease.lease_expiry,
                            )
                            changed = True
                        except Exception as exc:
                            logger.warning("Lease sweep cleanup failed for %s: %s",
                                           lease.ip_address, exc)
                    if changed:
                        expired_ids = [l.id for l in expired]
                        IPLease.query.filter(IPLease.id.in_(expired_ids)).delete(
                            synchronize_session=False
                        )
                        db.session.commit()

                    # Set internet_accessible=null for MACs with no active leases
                    try:
                        now2 = datetime.utcnow()
                        active_mac_ids = {
                            row[0]
                            for row in db.session.query(IPLease.mac_address).filter(
                                IPLease.lease_expiry > now2
                            ).all()
                        }
                        stale = Device.query.filter(
                            Device.internet_accessible.isnot(None),
                            Device.internet_blocked.isnot(True),
                        ).all()
                        changed_count = 0
                        for dev in stale:
                            if dev.mac_address not in active_mac_ids:
                                dev.internet_accessible = None
                                changed_count += 1
                        if changed_count:
                            db.session.commit()
                            logger.debug(
                                "Lease sweep: cleared internet_accessible for %d MAC(s) "
                                "with no active lease",
                                changed_count,
                            )
                    except Exception as exc:
                        logger.warning("Lease sweep: internet_accessible cleanup failed: %s", exc)

                finally:
                    db.session.remove()

        except Exception as exc:
            logger.warning("IP lease sweep failed: %s", exc)
        heartbeat('ip-lease-sweep')
        time.sleep(interval)


def start_ip_lease_sweeper(app) -> None:
    thread = threading.Thread(
        target=_sweep_expired_ip_leases,
        args=(app,),
        daemon=True,
        name='ip-lease-sweep',
    )
    thread.start()


# ---------------------------------------------------------------------------
# Startup hooks (called from create_app)
# ---------------------------------------------------------------------------

def startup_switch_discovery(app) -> None:
    """Trigger switch port discovery in a background thread shortly after startup."""

    def _run():
        time.sleep(5 + (os.getpid() % 4))

        lock_acquired = False

        # Phase 1: acquire the advisory lock and check whether discovery is needed.
        try:
            with app.app_context():
                from extensions import db
                from datetime import datetime, timedelta
                from sqlalchemy import text

                try:
                    lock_acquired = db.session.execute(
                        text("SELECT pg_try_advisory_lock(99001)")
                    ).scalar()

                    if not lock_acquired:
                        logger.info("Switch discovery lock held by another worker, skipping")
                        return

                    cutoff = datetime.utcnow() - timedelta(hours=24)
                    fresh = db.session.execute(
                        text(
                            "SELECT 1 FROM switch_ports "
                            "WHERE last_discovered > :cutoff LIMIT 1"
                        ),
                        {"cutoff": cutoff},
                    ).fetchone()

                    if fresh:
                        logger.info("Switch port discovery skipped – data is already fresh")
                        db.session.execute(text("SELECT pg_advisory_unlock(99001)"))
                        db.session.commit()
                        lock_acquired = False
                        return

                finally:
                    db.session.remove()

        except Exception as exc:
            logger.warning("Switch discovery startup: could not acquire/check lock: %s", exc)
            return

        # Phase 2: do the actual discovery inside an app context.
        try:
            logger.info("Background switch port discovery starting…")

            with app.app_context():
                from blueprints.admin.switch_ports import refresh_switch_ports

                results = refresh_switch_ports()

                for host, result in results.items():
                    logger.info("Switch discovery %s: %s", host, result)

        except Exception as exc:
            logger.warning("Background switch port discovery error: %s", exc)

        # Phase 3: release the advisory lock if this thread acquired it.
        finally:
            if lock_acquired:
                try:
                    with app.app_context():
                        from extensions import db
                        from sqlalchemy import text

                        try:
                            db.session.execute(text("SELECT pg_advisory_unlock(99001)"))
                            db.session.commit()
                        finally:
                            db.session.remove()

                except Exception:
                    pass

    threading.Thread(target=_run, daemon=True).start()
    

def startup_network_enforcement_baseline(app) -> None:
    """Push ACL/PBR baseline + re-apply all per-device blocks on startup.

    This ensures that after a restart (or new Gunicorn worker), both the
    structural ACLs (from hp5130-acl-baseline.sh) *and* all the per-IP
    block rules are present.
    """

    def _run():
        time.sleep(10 + (os.getpid() % 4))

        # --- Advisory lock so only one worker does the startup push ---
        try:
            lock_acquired = False
            with app.app_context():
                from extensions import db
                from sqlalchemy import text
                try:
                    lock_acquired = db.session.execute(
                        text("SELECT pg_try_advisory_lock(99002)")
                    ).scalar()
                finally:
                    db.session.remove()

            if not lock_acquired:
                logger.info("ACL baseline lock held by another worker, skipping")
                return
        except Exception as exc:
            logger.warning("ACL baseline startup: could not acquire lock: %s", exc)
            return

        try:
            logger.info("Startup ACL baseline push starting…")

            with app.app_context():
                from core.network import reset_acl_baseline, reapply_all_ip_blocks

                # 1. Push structural ACL/PBR baseline
                ok = reset_acl_baseline()
                if not ok:
                    logger.warning("Startup ACL baseline push failed")

                # 2. Re-apply all per-device blocks (critical — baseline wipes them)
                try:
                    pushed, failed = reapply_all_ip_blocks()
                    if failed > 0:
                        logger.warning(
                            "Startup re-apply of per-device blocks: %d pushed, %d failed",
                            pushed, failed
                        )
                    else:
                        logger.info("Startup re-apply of per-device blocks completed (%d pushed)", pushed)
                except Exception as exc:
                    logger.exception("Failed to re-apply per-device blocks on startup: %s", exc)

            logger.info("Startup ACL baseline + per-device blocks push finished")

        except Exception as exc:
            logger.warning("Startup ACL baseline push error: %s", exc)

        finally:
            # Release advisory lock
            try:
                with app.app_context():
                    from extensions import db
                    from sqlalchemy import text
                    db.session.execute(text("SELECT pg_advisory_unlock(99002)"))
                    db.session.commit()
                    db.session.remove()
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()


def startup_write_prefix_map(app) -> None:
    """Write vlan-prefix-map.txt from the DB on startup."""

    def _run():
        with app.app_context():
            from extensions import db
            from sqlalchemy import text
            try:
                lock_acquired = db.session.execute(
                    text("SELECT pg_try_advisory_lock(99003)")
                ).scalar()
                if not lock_acquired:
                    db.session.remove()
                    return
                from core.vlan_utils import get_vlan_prefix_by_id
                prefix_by_id = get_vlan_prefix_by_id()
                if not prefix_by_id:
                    db.session.execute(text("SELECT pg_advisory_unlock(99003)"))
                    db.session.commit()
                    db.session.remove()
                    return
                config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
                prefix_map_path = os.path.join(
                    os.path.dirname(config_path), 'vlan-prefix-map.txt'
                )
                prefix_map_str = ','.join(
                    f"{vid}:{pfx}" for vid, pfx in sorted(prefix_by_id.items())
                )
                with open(prefix_map_path, 'w', encoding='utf-8') as f:
                    f.write(prefix_map_str + '\n')
                logger.info("Wrote vlan-prefix-map.txt: %s", prefix_map_str)
            except Exception as exc:
                logger.warning("Could not write vlan-prefix-map.txt: %s", exc)
            finally:
                try:
                    db.session.execute(text("SELECT pg_advisory_unlock(99003)"))
                    db.session.commit()
                    db.session.remove()
                except Exception:
                    pass

    threading.Thread(target=_run, daemon=True).start()


def startup_dns_hijack_blocked_pools(app) -> None:
    """Ensure DNS hijacking for blocked pools is active after startup."""

    def _run():
        time.sleep(12)
        try:
            script_path = os.getenv('DNS_SCRIPT', '/scripts/dns-hijack.sh')
            if not os.path.isfile(script_path):
                logger.error("DNS hijack script not found: %s", script_path)
                return

            result = subprocess.run(
                [script_path, "refresh-blocked-pools"],   # ← changed
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                if result.stdout.strip():
                    logger.info("DNS hijack startup output:\n%s", result.stdout.strip())
                logger.info("Startup DNS hijack for blocked pools applied successfully")
            else:
                logger.warning(
                    "Startup DNS hijack failed (exit=%s)\nSTDOUT:\n%s\nSTDERR:\n%s",
                    result.returncode,
                    result.stdout.strip() or '<empty>',
                    result.stderr.strip() or '<empty>'
                )
        except Exception as exc:
            logger.warning("Failed to apply startup blocked-pool DNS hijack: %s", exc)   

    threading.Thread(target=_run, daemon=True).start()    