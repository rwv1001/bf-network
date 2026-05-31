"""
Captive-portal URL builders and WiFi confirmation helpers.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import request, url_for

logger = logging.getLogger(__name__)


def get_portal_base_url() -> str:
    portal_url = os.getenv('PORTAL_URL', '').strip()
    return portal_url.rstrip('/') if portal_url else ''


def build_portal_url(path: str) -> str:
    base = get_portal_base_url()
    if base:
        return f"{base}{path}"
    return path


def portal_host_mismatch() -> bool:
    portal_url = get_portal_base_url()
    if not portal_url:
        return False
    try:
        portal_host = urlparse(portal_url).netloc
    except Exception:
        return False
    return bool(portal_host and portal_host != request.host)


def build_unregister_url(token: str) -> str:
    portal_url = get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}{url_for('portal.unregister', token=token)}"
    return url_for('portal.unregister', token=token, _external=True)


def build_confirm_url(token: str) -> str:
    portal_url = get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}{url_for('portal.confirm_device', token=token)}"
    return url_for('portal.confirm_device', token=token, _external=True)


def build_reject_url(token: str) -> str:
    portal_url = get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}{url_for('portal.reject_device', token=token)}"
    return url_for('portal.reject_device', token=token, _external=True)


def build_set_password_url(token: str) -> str:
    portal_url = get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return (
            f"{parsed.scheme}://{parsed.netloc}"
            f"{url_for('portal.set_network_password', token=token)}"
        )
    return url_for('portal.set_network_password', token=token, _external=True)


def build_admin_set_password_url(approval_token: str) -> str:
    portal_url = get_portal_base_url()
    if portal_url:
        parsed = urlparse(portal_url)
        return (
            f"{parsed.scheme}://{parsed.netloc}"
            f"{url_for('admin.approvals.set_user_password', token=approval_token)}"
        )
    return url_for('admin.approvals.set_user_password', token=approval_token, _external=True)


# ---------------------------------------------------------------------------
# WiFi confirmation helpers
# ---------------------------------------------------------------------------

def wifi_confirm_timeout_sec() -> int:
    raw = os.getenv('WIFI_CONFIRM_TIMEOUT_SEC', '120').strip()
    try:
        value = int(raw)
    except ValueError:
        value = 120
    return value if value > 0 else 120


def wifi_confirm_timeout_minutes() -> int:
    """Return the WiFi confirmation timeout rounded up to whole minutes."""
    return max(1, int((wifi_confirm_timeout_sec() + 59) / 60))


def wifi_confirm_sweep_interval_sec() -> int:
    raw = os.getenv('WIFI_CONFIRM_SWEEP_INTERVAL_SEC', '30').strip()
    try:
        value = int(raw)
    except ValueError:
        value = 30
    return value if value > 0 else 30


def set_wifi_confirmation(device) -> tuple:
    """
    Set a confirmation token and deadline on a device.
    Returns (confirm_url, reject_url, timeout_sec).
    """
    from extensions import db
    timeout_sec = wifi_confirm_timeout_sec()
    device.confirmation_token = secrets.token_urlsafe(32)
    device.confirmation_confirmed_at = None
    device.confirmation_deadline = datetime.utcnow() + timedelta(seconds=timeout_sec)
    db.session.commit()
    confirm_url = build_confirm_url(device.confirmation_token)
    reject_url = build_reject_url(device.confirmation_token)
    return confirm_url, reject_url, timeout_sec


def enforce_wifi_confirmation(device):
    """
    If a device's WiFi confirmation has expired, unregister it.
    Returns the (possibly unregistered) device.
    """
    if not device:
        return device
    if device.registration_status != 'registered':
        return device
    if not device.confirmation_deadline or device.confirmation_confirmed_at:
        return device
    if datetime.utcnow() < device.confirmation_deadline:
        return device
    logger.info("WiFi confirmation expired for %s; unregistering device", device.mac_address)
    from core.device_utils import unregister_device
    unregister_device(device)
    return device


def build_prefill_from_request() -> dict:
    """Extract registration form prefill values from request args."""
    return {
        'email':        request.args.get('email', '').strip(),
        'first_name':   request.args.get('first_name', '').strip(),
        'last_name':    request.args.get('last_name', '').strip(),
        'phone_number': request.args.get('phone_number', '').strip(),
        'device_type':  request.args.get('device_type', '').strip(),
    }
