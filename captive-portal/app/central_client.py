"""
central_client.py — bf-network integration with the bf-central sync server.

Responsibilities:
  1. Queue outbound events to central (device/user registered/blocked/unblocked)
  2. Drain the outbound queue in a background thread (with retry on failure)
  3. Expose _apply_inbound() for the /api/v1/push HTTP endpoint (central pushes
     updates directly to this site rather than this site polling for them)
  4. Look up an unknown MAC address at central when the local DB has no record

Central integration is opt-in: if CENTRAL_API_URL or CENTRAL_API_KEY are absent
from the environment the module silently does nothing, so existing
single-site deployments are unaffected.
"""

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration read from environment
# ---------------------------------------------------------------------------

def _central_enabled() -> bool:
    return bool(
        os.getenv("CENTRAL_API_URL", "").strip()
        and os.getenv("CENTRAL_API_KEY", "").strip()
        and os.getenv("CENTRAL_SITE_ID", "").strip()
    )

def _api_url() -> str:
    return os.getenv("CENTRAL_API_URL", "").rstrip("/")

def _headers() -> dict:
    return {
        "X-API-Key": os.getenv("CENTRAL_API_KEY", ""),
        "Content-Type": "application/json",
    }

_TIMEOUT = int(os.getenv("CENTRAL_REQUEST_TIMEOUT_SEC", "8"))
_POLL_INTERVAL = int(os.getenv("CENTRAL_POLL_INTERVAL_SEC", "10"))

# ---------------------------------------------------------------------------
# Module-level app reference (set by init_central_client)
# ---------------------------------------------------------------------------

_app = None         # Flask app — needed for background threads that need app context
_db = None          # SQLAlchemy db instance
_model = None       # CentralOutboundEvent model class


def init_central_client(app, db, central_event_model):
    """
    Call once at startup (after db.create_all) to wire up the background workers.
    Pass the Flask app, db instance, and the CentralOutboundEvent model class.
    """
    global _app, _db, _model
    _app = app
    _db = db
    _model = central_event_model

    if not _central_enabled():
        logger.info("Central sync disabled (CENTRAL_API_URL/KEY/SITE_ID not set)")
        return

    logger.info(
        "Central sync enabled: site=%s url=%s",
        os.getenv("CENTRAL_SITE_ID"),
        _api_url(),
    )

    threading.Thread(
        target=_outbound_worker, daemon=True, name="central-outbound"
    ).start()


# ---------------------------------------------------------------------------
# Public API — called from blueprints / app.py
# ---------------------------------------------------------------------------

def queue_device_registered(device, user) -> None:
    """Queue a device_registered event to central after successful local registration.

    Also kicks off an immediate eager send in a background thread so central has
    the record before the next scheduled poll cycle (avoids up to
    CENTRAL_POLL_INTERVAL_SEC of delay that causes central_import.py to return
    not_found when the device reconnects shortly after registration).
    """
    if not _central_enabled():
        return
    payload = {
        "mac_address": device.mac_address,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "phone_number": user.phone_number,
        "network_password_hash": user.network_password_hash or "",
        "assigned_vlan": device.assigned_vlan,
        "device_name": device.device_name,
        "is_wired": bool(device.is_wired),
        "connection_type": device.connection_type or "unknown",
    }
    _enqueue("device_registered", payload)
    # Attempt an immediate send without waiting for the poll cycle.
    # The async worker still provides the retry path if this fails.
    if _app and _model and _db:
        threading.Thread(
            target=_eager_send_registration,
            args=(payload,),
            daemon=True,
            name="central-eager-reg",
        ).start()


def queue_device_blocked(device, reason: Optional[str] = None) -> None:
    if not _central_enabled():
        return
    _enqueue("device_blocked", {
        "mac_address": device.mac_address,
        "reason": reason or "",
    })


def queue_device_unblocked(device) -> None:
    if not _central_enabled():
        return
    _enqueue("device_unblocked", {"mac_address": device.mac_address})


def queue_device_unregistered(mac_address: str) -> None:
    """Queue a device_unregistered event to central after a device is unregistered locally.

    Central will remove this site's SiteDeviceRegistration and push an
    unregister_device instruction to every other site that still holds the device,
    so no other site grants that device internet access under the former owner's
    account.
    """
    if not _central_enabled():
        return
    _enqueue("device_unregistered", {"mac_address": mac_address})


def queue_device_reassigned(device, old_user, new_user) -> None:
    """Queue a device_reassigned event after an admin transfers a device to a new owner."""
    if not _central_enabled():
        return
    _enqueue("device_reassigned", {
        "mac_address": device.mac_address,
        "old_email":   old_user.email if old_user else None,
        "email":       new_user.email,
        "first_name":  new_user.first_name or "",
        "last_name":   new_user.last_name  or "",
        "phone_number": new_user.phone_number or "",
        "network_password_hash": new_user.network_password_hash or "",
    })


def queue_device_vlan_changed(device) -> None:
    """Queue a device_vlan_changed event after an admin changes a wired device's VLAN.

    Central will fan this out to every other site that holds a registration for
    this device, so their local RADIUS/Kea configs are updated and the device
    gets the correct VLAN wherever it connects next.
    """
    if not _central_enabled():
        return
    _enqueue("device_vlan_changed", {
        "mac_address": device.mac_address,
        "assigned_vlan": device.assigned_vlan,
        "is_wired": bool(device.is_wired),
        "connection_type": device.connection_type or "wired",
    })


def queue_user_blocked(user, reason: Optional[str] = None) -> None:
    if not _central_enabled():
        return
    _enqueue("user_blocked", {
        "email": user.email,
        "reason": reason or "",
    })


def queue_user_unblocked(user) -> None:
    if not _central_enabled():
        return
    _enqueue("user_unblocked", {"email": user.email})


def queue_user_updated(user) -> None:
    """Queue a user_updated event after a profile or VLAN-override change.

    Propagates name, phone, and VLAN-override fields to central, which fans
    the update out to any other sites that hold this user.
    """
    if not _central_enabled():
        return
    _enqueue("user_updated", {
        "email":                    user.email,
        "first_name":               user.first_name   or "",
        "last_name":                user.last_name    or "",
        "phone_number":             user.phone_number or "",
        "network_password_hash":    user.network_password_hash or "",
        "allowed_vlans_override":   user.allowed_vlans_override   or "",
        "allowed_vlans_deny":       user.allowed_vlans_deny       or "",
        "adoptable_vlans_override": user.adoptable_vlans_override or "",
        "adoptable_vlans_deny":     user.adoptable_vlans_deny     or "",
    })


def import_device_from_central(mac_address: str, central_data: dict) -> Optional[object]:
    """Import a device+user from a central lookup response into the local DB.

    Creates or updates the local User, Device, and DeviceOwnership records, then
    queues a device_registered event so central knows this site now holds the
    device.

    Returns the local Device object (which may have internet_blocked=True if
    central reported it blocked), or None on failure.

    The caller must be inside a Flask app context.
    """
    if not central_data:
        return None

    from models import Device, User, DeviceOwnership
    from app import db as app_db
    import datetime as _dt

    mac = mac_address.lower().strip()
    email = (central_data.get("email") or "").lower().strip()
    if not email:
        logger.warning("import_device_from_central: no email in central data for %s", mac)
        return None

    now = _dt.datetime.now(_dt.timezone.utc)

    # Upsert user
    user = User.query.filter_by(email=email).first()
    if not user:
        network_password_hash = central_data.get("network_password_hash") or None
        user = User(
            email=email,
            first_name=central_data.get("first_name") or "",
            last_name=central_data.get("last_name") or "",
            phone_number=central_data.get("phone_number") or "",
            network_password_hash=network_password_hash,
            network_password_approval_mode='first_use' if network_password_hash else None,
            begin_date=now.date(),
        )
        app_db.session.add(user)
        app_db.session.flush()
        logger.info("import_device_from_central: created user %s from central", email)
    else:
        # Fill gaps only — don't overwrite locally-set values
        if not user.first_name and central_data.get("first_name"):
            user.first_name = central_data["first_name"]
        if not user.last_name and central_data.get("last_name"):
            user.last_name = central_data["last_name"]
        if not user.network_password_hash and central_data.get("network_password_hash"):
            user.network_password_hash = central_data["network_password_hash"]
            if not user.network_password_approval_mode:
                user.network_password_approval_mode = 'first_use'

    # Apply user-level block from central
    if central_data.get("user_blocked") and not getattr(user, "blocked", False):
        user.blocked = True
        logger.info("import_device_from_central: user %s marked blocked (from central)", email)

    # Upsert device
    device = Device.query.filter_by(mac_address=mac).first()
    device_blocked = bool(central_data.get("device_blocked") or central_data.get("user_blocked"))
    is_wired_device = bool(central_data.get("is_wired"))
    central_vlan = central_data.get("assigned_vlan")
    if not device:
        device = Device(
            mac_address=mac,
            assigned_vlan=central_vlan,
            device_name=central_data.get("device_name"),
            internet_blocked=device_blocked,
            first_seen=now,
            is_wired=is_wired_device,
            connection_type="wired" if is_wired_device else (central_data.get("connection_type") or "unknown"),
        )
        app_db.session.add(device)
        app_db.session.flush()
        logger.info("import_device_from_central: created device %s (blocked=%s)", mac, device_blocked)
    else:
        if device_blocked and not device.internet_blocked:
            device.internet_blocked = True
            logger.info("import_device_from_central: device %s marked blocked (from central)", mac)
        if not device.assigned_vlan and central_vlan:
            device.assigned_vlan = central_vlan
        if is_wired_device:
            device.is_wired = True
            device.connection_type = "wired"

    # Upsert ownership
    existing_ownership = DeviceOwnership.query.filter_by(
        mac_address=mac, end_datetime=None
    ).first()
    if not existing_ownership:
        ownership = DeviceOwnership(
            mac_address=mac,
            user_id=user.id,
            start_datetime=now,
            end_datetime=None,
        )
        app_db.session.add(ownership)

    device.ownership_validated = True

    # Wired cross-site: trigger port bounce if on wrong VLAN
    # The device arrived on VLAN 250 (wired_unregistered). RADIUS placed it
    # there because it had no local record. Now that we've imported it, queue a
    # port bounce so the switch re-auths via RADIUS, which will now return the
    # correct VLAN. A short-lease expiry alone is NOT sufficient — DHCP DISCOVER
    # goes out on whatever VLAN the switch port is currently on, not the target.
    needs_bounce = False
    if is_wired_device and central_vlan and not device_blocked:
        from app import _get_wired_unregistered_vlan_id
        wired_unreg_vlan = _get_wired_unregistered_vlan_id()
        current_vlan = getattr(device, 'current_vlan', None)
        if current_vlan in (None, wired_unreg_vlan) or current_vlan != central_vlan:
            device.registration_status = "wrong_vlan"
            device.wired_target_vlan = central_vlan
            needs_bounce = True

    app_db.session.commit()

    if needs_bounce:
        try:
            from app import replug_switch_port_for_mac
            replug_switch_port_for_mac(mac)
            logger.info(
                "import_device_from_central: wired device %s on wrong VLAN — port bounce queued",
                mac,
            )
        except Exception as exc:
            logger.warning("import_device_from_central: port bounce failed for %s: %s", mac, exc)

    # Notify central this site now holds the device
    queue_device_registered(device, user)

    return device


def lookup_device_at_central(mac_address: str) -> Optional[dict]:
    """
    Query central for an unknown MAC address.
    Returns a dict with device/user info + block status, or None if not found
    or central is unreachable (fail-open).

    The caller is responsible for creating local DB records from the response.
    """
    if not _central_enabled():
        return None
    logger.info("central lookup: querying %s for MAC %s", _api_url(), mac_address)
    try:
        resp = requests.get(
            f"{_api_url()}/api/v1/device/{mac_address}",
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            logger.info("central lookup: found MAC %s at central", mac_address)
            return resp.json()
        if resp.status_code == 404:
            logger.info("central lookup: MAC %s not known to central", mac_address)
            return None
        logger.warning("central lookup %s → HTTP %d", mac_address, resp.status_code)
    except Exception as exc:
        logger.warning("central lookup %s failed (fail-open): %s", mac_address, exc)
    return None


def lookup_user_at_central(email: str) -> Optional[dict]:
    """
    Query central for a known user by email address.
    Returns a dict with first_name, last_name, phone_number (and blocked status),
    or None if not found or central is unreachable (fail-open).

    Used during the step-1 registration check to pre-fill name fields when the
    user has already registered at a different site.
    """
    if not _central_enabled():
        return None
    logger.info("central user lookup: querying %s for email %s", _api_url(), email)
    try:
        import urllib.parse
        encoded = urllib.parse.quote(email, safe="")
        resp = requests.get(
            f"{_api_url()}/api/v1/user/{encoded}",
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            logger.info("central user lookup: found email %s at central", email)
            return resp.json()
        if resp.status_code == 404:
            logger.info("central user lookup: email %s not known to central", email)
            return None
        logger.warning("central user lookup %s → HTTP %d", email, resp.status_code)
    except Exception as exc:
        logger.warning("central user lookup %s failed (fail-open): %s", email, exc)
    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _enqueue(event_type: str, payload: dict) -> None:
    """Insert and commit an outbound event into the local DB queue.
    Uses a separate commit so the event is persisted regardless of whether
    the caller's transaction has already been committed."""
    if _model is None or _db is None:
        return
    try:
        event = _model(event_type=event_type, payload=payload)
        _db.session.add(event)
        _db.session.commit()
    except Exception as exc:
        _db.session.rollback()
        logger.error("Failed to enqueue central event %s: %s", event_type, exc)


def _send_event(event_type: str, payload: dict):
    """Send a single event to central.
    Returns the parsed JSON response dict on success, False on failure."""
    try:
        resp = requests.post(
            f"{_api_url()}/api/v1/event",
            json={
                "event_type": event_type,
                "source_site_id": os.getenv("CENTRAL_SITE_ID", ""),
                "data": payload,
            },
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        if resp.status_code in (200, 201):
            try:
                return resp.json()
            except Exception:
                return {"status": "ok"}
        # 4xx errors (except 429) are permanent failures — the central server
        # will never accept this event, so don't retry it.
        if resp.status_code != 429 and 400 <= resp.status_code < 500:
            logger.debug("central event %s → HTTP %d (permanent, dropping): %s",
                         event_type, resp.status_code, resp.text[:200])
            return {"_dropped": True}
        logger.warning("central event %s → HTTP %d: %s", event_type, resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.warning("central event %s failed: %s", event_type, exc)
    return False


def _eager_send_registration(payload: dict) -> None:
    mac = payload.get("mac_address", "").lower()
    with _app.app_context():

        from extensions import db
        try:
            result = _send_event("device_registered", payload)
            if result and not (isinstance(result, dict) and result.get("_dropped")):
                # === ROBUST VERSION - no JSON operators needed ===
                recent_pending = (
                    _model.query
                    .filter_by(event_type="device_registered", status="pending")
                    .order_by(_model.created_at.desc())
                    .limit(30)          # plenty — queue is tiny
                    .all()
                )
                event = next(
                    (e for e in recent_pending 
                     if isinstance(e.payload, dict) and e.payload.get("mac_address") == mac),
                    None
                )
                if event:
                    event.status = "sent"
                    event.attempts = (event.attempts or 0) + 1
                    event.last_attempt_at = datetime.now(timezone.utc)
                    db.session.commit()

                if isinstance(result, dict):
                    _handle_registration_response(payload, result)

                logger.info("central eager send: device_registered for %s succeeded", mac)
            else:
                logger.info("central eager send: device_registered for %s failed/dropped, "
                            "worker will retry", mac)
        except Exception as exc:
            db.session.rollback()
            logger.warning("central eager send for %s failed: %s — worker will retry", mac, exc)
        finally:
            db.session.remove()


def _outbound_worker() -> None:
    """Daemon thread: drain the outbound queue, retrying failed items.

    For device_registered events, central's response includes the current
    block state.  If the device is blocked (e.g. it was blocked at another
    site before arriving here), apply the block locally so the correct Kea
    reservation and ACLs are set without waiting for a separate inbound
    instruction.
    """
    while True:
        time.sleep(_POLL_INTERVAL)
        if not _app or not _model or not _db:
            continue
        try:
            with _app.app_context():
                # db imported inside context — must not be imported at module level
                from extensions import db
                try:
                    pending = (
                        _model.query
                        .filter_by(status="pending")
                        .order_by(_model.created_at)
                        .limit(50)
                        .all()
                    )
                    for item in pending:
                        result = _send_event(item.event_type, item.payload)
                        success = bool(result)
                        item.attempts += 1
                        item.last_attempt_at = datetime.now(timezone.utc)
                        item.status = "sent" if success else "pending"
                        # For device_registered, central tells us whether the
                        # device/user is blocked at another site.
                        if success and not isinstance(result, dict) or (isinstance(result, dict) and not result.get("_dropped")):
                            if item.event_type == "device_registered" and isinstance(result, dict):
                                _handle_registration_response(item.payload, result)
                    if pending:
                        db.session.commit()
                    # Prune sent events older than 48 h — central_import.py's
                    # fallback only looks back 24 h, so these are never needed again.
                    from sqlalchemy import text as _text
                    db.session.execute(_text(
                        "DELETE FROM central_outbound_events"
                        " WHERE status = 'sent'"
                        "   AND created_at < NOW() - INTERVAL '48 hours'"
                    ))
                    db.session.commit()
                except Exception as exc:
                    db.session.rollback()
                    logger.error("outbound worker error: %s", exc)
                finally:
                    db.session.remove()
        except Exception as exc:
            logger.error("outbound worker error (context): %s", exc)
        try:
            from app import _heartbeat
            _heartbeat('central-outbound')
        except Exception:
            pass


def _handle_registration_response(payload: dict, central_response: dict) -> None:
    """After central ACKs a device_registered event, apply any block the central
    server indicates is already in effect for that device or its user.

    Must be called from within an active app context (e.g. inside _outbound_worker
    or _eager_send_registration).
    """
    from models import Device, User, DeviceOwnership
    from extensions import db

    mac = payload.get("mac_address", "").lower()
    if not mac:
        return

    device = Device.query.filter_by(mac_address=mac).first()
    if not device:
        return

    if central_response.get("device_blocked") and not device.internet_blocked:
        logger.info("central: device %s is blocked at another site — applying block locally", mac)
        from core.network import apply_device_block
        apply_device_block(device, flash_messages=False)
        return

    if central_response.get("user_blocked"):
        email = payload.get("email", "").lower()
        user = User.query.filter_by(email=email).first() if email else None
        if user and not getattr(user, "blocked", False):
            logger.info("central: user %s is blocked at another site — applying block locally", email)
            user.blocked = True
            db.session.commit()
            active_macs = [
                o.mac_address for o in
                DeviceOwnership.query.filter_by(user_id=user.id, end_datetime=None).all()
            ]
            from core.network import apply_device_block
            for d in Device.query.filter(Device.mac_address.in_(active_macs)).all():
                apply_device_block(d, flash_messages=False)


def _apply_inbound(event_type: str, data: dict) -> None:
    """Apply an instruction received from central to the local DB and network.

    Called from the /api/v1/push endpoint which already has a request (and
    therefore app) context active.
    """
    from models import Device, User, DeviceOwnership
    from extensions import db
    from core.network import apply_device_block, apply_device_unblock

    logger.info("central inbound: %s %s", event_type, data)

    if event_type in ("block_device", "device_blocked"):
        mac = data.get("mac_address", "").lower()
        device = Device.query.filter_by(mac_address=mac).first()
        if device:
            apply_device_block(device, flash_messages=False, notify_central=False)
            logger.info("central: blocked device %s", mac)
        else:
            logger.warning("central block_device: MAC %s not found locally", mac)

    elif event_type in ("unblock_device", "device_unblocked"):
        mac = data.get("mac_address", "").lower()
        device = Device.query.filter_by(mac_address=mac).first()
        if device:
            apply_device_unblock(device, flash_messages=False, notify_central=False)
            logger.info("central: unblocked device %s", mac)

    elif event_type == "block_user":
        email = data.get("email", "").lower()
        user = User.query.filter_by(email=email).first()
        if user:
            user.blocked = True
            db.session.commit()
            active_macs = [
                o.mac_address for o in
                DeviceOwnership.query.filter_by(user_id=user.id, end_datetime=None).all()
            ]
            for device in Device.query.filter(Device.mac_address.in_(active_macs)).all():
                apply_device_block(device, flash_messages=False, notify_central=False)
            logger.info("central: blocked user %s", email)
        else:
            logger.warning("central block_user: email %s not found locally", email)

    elif event_type == "unblock_user":
        email = data.get("email", "").lower()
        user = User.query.filter_by(email=email).first()
        if user:
            user.blocked = False
            db.session.commit()
            logger.info("central: unblocked user %s (devices remain individually blocked)", email)

    elif event_type == "update_user":
        email = data.get("email", "").lower()
        user = User.query.filter_by(email=email).first()
        if user:
            if data.get("first_name") is not None:
                user.first_name = data["first_name"]
            if data.get("last_name") is not None:
                user.last_name = data["last_name"]
            if data.get("phone_number") is not None:
                user.phone_number = data["phone_number"]
            # Propagate network password hash so cross-site password entry works
            if data.get("network_password_hash"):
                user.network_password_hash = data["network_password_hash"]
                # If they didn't have a password before, set mode to first_use
                if not user.network_password_approval_mode:
                    user.network_password_approval_mode = 'first_use'
            if data.get("allowed_vlans_override") is not None:
                user.allowed_vlans_override = data["allowed_vlans_override"] or None
            if data.get("allowed_vlans_deny") is not None:
                user.allowed_vlans_deny = data["allowed_vlans_deny"] or None
            if data.get("adoptable_vlans_override") is not None:
                user.adoptable_vlans_override = data["adoptable_vlans_override"] or None
            if data.get("adoptable_vlans_deny") is not None:
                user.adoptable_vlans_deny = data["adoptable_vlans_deny"] or None
            db.session.commit()
            logger.info("central: updated profile for user %s", email)
        else:
            logger.info("central update_user: %s not found locally — skipping", email)

    elif event_type == "update_device_vlan":
        from app import replug_switch_port_for_mac
        mac = data.get("mac_address", "").lower()
        new_vlan = data.get("assigned_vlan")
        device = Device.query.filter_by(mac_address=mac).first()
        if not device:
            logger.info("central update_device_vlan: MAC %s not found locally — skipping", mac)
            return
        if not new_vlan:
            logger.warning("central update_device_vlan: no assigned_vlan in payload for %s", mac)
            return
        # If this device has no active local ownership (admin deleted it), do not
        # let a stale central push re-assign an assigned_vlan — local admin wins.
        if device.user_id is None:
            logger.info(
                "central update_device_vlan: device %s has no local owner — ignoring central push",
                mac,
            )
            return
        old_vlan = device.current_vlan
        device.assigned_vlan = new_vlan
        device.wired_target_vlan = new_vlan
        device.is_wired = True
        device.connection_type = "wired"
        if old_vlan != new_vlan:
            device.registration_status = "wrong_vlan"
        db.session.commit()
        # Trigger RADIUS re-auth via port bounce — this is the only reliable
        # way to move a wired device to a new VLAN (short lease expiry alone
        # won't help because DHCP DISCOVER still goes out on the current VLAN).
        replug_switch_port_for_mac(mac)
        logger.info(
            "central: updated wired device %s VLAN %s → %s, port bounce queued",
            mac, old_vlan, new_vlan,
        )

    elif event_type == "reassign_device":
        mac       = data.get("mac_address", "").lower()
        new_email = (data.get("email") or "").lower().strip()
        if not new_email:
            logger.warning("central reassign_device: no email in payload for %s", mac)
            return
        device = Device.query.filter_by(mac_address=mac).first()
        if not device:
            logger.info("central reassign_device: MAC %s not found locally — skipping", mac)
            return
        user = User.query.filter_by(email=new_email).first()
        if not user:
            import datetime as _dt
            user = User(
                email=new_email,
                first_name=data.get("first_name") or "",
                last_name=data.get("last_name")  or "",
                phone_number=data.get("phone_number") or "",
                begin_date=_dt.date.today(),
            )
            db.session.add(user)
            db.session.flush()
        from core.device_utils import close_ownership, open_ownership
        close_ownership(mac, commit=False)
        open_ownership(mac, user_id=user.id, commit=False)
        db.session.commit()
        logger.info("central: reassigned device %s to %s via central push", mac, new_email)

    elif event_type == "unregister_device":
        from core.device_utils import close_ownership, sync_registration_status
        from core.vlan_utils import parse_valid_vlan_ids
        from kea_integration import get_kea_client
        mac = data.get("mac_address", "").lower()
        device = Device.query.filter_by(mac_address=mac).first()
        if not device:
            logger.info("central unregister_device: MAC %s not found locally — skipping", mac)
            return

        vlan_id = device.assigned_vlan or device.current_vlan
        kea_socket = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
        kea = get_kea_client(control_socket=kea_socket)
        if kea:
            if vlan_id:
                kea.unregister_mac(mac=mac, vlan=vlan_id)
            else:
                for vid in parse_valid_vlan_ids():
                    kea.unregister_mac(mac=mac, vlan=vid)

        if device.connection_type == 'wired':
            from radius_coa import send_coa_disconnect
            send_coa_disconnect(mac)

        close_ownership(mac, commit=False)
        device.device_name = None
        device.assigned_vlan = None
        device.current_vlan = None
        device.wired_target_vlan = None
        device.internet_accessible = None
        device.internet_blocked = None
        device.ownership_validated = None
        device.unregister_token = None
        device.profile_snapshot = None
        device.stale = True
        sync_registration_status(device)
        db.session.commit()
        logger.info("central: unregistered device %s via central push", mac)

    else:
        logger.warning("central: unknown inbound event_type %r", event_type)
