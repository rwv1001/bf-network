"""
Device and IP-lease state helpers (Spec Tables 6, 7, 9).

Covers:
- DeviceOwnership (Table 9) open/close helpers
- IPLease (Table 7) upsert/expire helpers
- Table-6 state setters (internet_accessible, internet_blocked)
- Device unregistration
- UnregisteredLease helpers
- reset_test_data()
"""

import logging
import os
from datetime import datetime

from sqlalchemy import text

from extensions import db
from models import (
    Device, DeviceOwnership, IPLease, RegistrationRequest,
    UnregisteredLease, User,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Spec Table 9 — DeviceOwnership helpers
# ---------------------------------------------------------------------------

def get_active_ownership(mac_address: str):
    """Return the active DeviceOwnership row for mac_address, or None."""
    return DeviceOwnership.query.filter_by(
        mac_address=mac_address, end_datetime=None
    ).first()


def open_ownership(mac_address: str, user_id: int, commit: bool = True):
    """Open a new DeviceOwnership row for mac_address/user_id."""
    o = DeviceOwnership(
        mac_address=mac_address,
        user_id=user_id,
        start_datetime=datetime.utcnow(),
    )
    db.session.add(o)
    if commit:
        db.session.commit()
    return o


def close_ownership(mac_address: str, commit: bool = True):
    """Close the active DeviceOwnership for mac_address (set end_datetime=now)."""
    o = get_active_ownership(mac_address)
    if o:
        o.end_datetime = datetime.utcnow()
        if commit:
            db.session.commit()
    return o


# ---------------------------------------------------------------------------
# Spec Table 7 — IPLease helpers
# ---------------------------------------------------------------------------

def get_active_iplease(mac_address: str):
    """Return the most recent non-expired IPLease for mac_address, or None."""
    return (
        IPLease.query
        .filter(
            IPLease.mac_address == mac_address,
            IPLease.lease_expiry > datetime.utcnow(),
        )
        .order_by(IPLease.lease_start.desc())
        .first()
    )


def upsert_iplease(mac_address, ip_address, vlan_id, lease_start, lease_expiry,
                   from_blocked_pool=False, dns_hijacked=False, commit=True):
    """Create or update an IPLease row for (mac_address, ip_address)."""
    lease = IPLease.query.filter_by(
        mac_address=mac_address, ip_address=ip_address
    ).first()
    if lease:
        lease.vlan_id = vlan_id
        lease.lease_start = lease_start
        lease.lease_expiry = lease_expiry
        lease.from_blocked_pool = from_blocked_pool
        lease.dns_hijacked = dns_hijacked
    else:
        lease = IPLease(
            ip_address=ip_address,
            vlan_id=vlan_id,
            mac_address=mac_address,
            lease_start=lease_start,
            lease_expiry=lease_expiry,
            from_blocked_pool=from_blocked_pool,
            dns_hijacked=dns_hijacked,
        )
        db.session.add(lease)
    if commit:
        db.session.commit()
    return lease


def expire_iplease(mac_address: str, ip_address: str, commit: bool = True):
    """Mark a specific IPLease as expired (set lease_expiry to now)."""
    lease = IPLease.query.filter_by(
        mac_address=mac_address, ip_address=ip_address
    ).first()
    if lease:
        lease.lease_expiry = datetime.utcnow()
        if commit:
            db.session.commit()
    return lease


# ---------------------------------------------------------------------------
# Spec Table 6 — state helpers
# ---------------------------------------------------------------------------

def sync_registration_status(device: Device) -> None:
    """Keep registration_status consistent with the orthogonal Table-6 fields."""
    if device.internet_blocked:
        device.registration_status = 'blocked'
    elif device.internet_accessible and device.assigned_vlan:
        device.registration_status = 'registered'
    elif device.internet_accessible is False and device.assigned_vlan:
        device.registration_status = 'wrong_vlan'
    else:
        device.registration_status = 'pending'


def set_internet_accessible(device: Device, value, commit: bool = True) -> None:
    """Set internet_accessible and keep registration_status in sync."""
    device.internet_accessible = value
    sync_registration_status(device)
    if commit:
        db.session.commit()


def set_internet_blocked(device: Device, value, commit: bool = True) -> None:
    """Set internet_blocked and keep registration_status in sync."""
    device.internet_blocked = value
    if value:
        device.internet_accessible = None
    sync_registration_status(device)
    if commit:
        db.session.commit()


def should_have_internet(device: Device) -> bool:
    """
    Return True if all conditions are met for the device to have internet access.
    Conditions: assigned_vlan set, current_vlan == assigned_vlan,
    password validated if required.
    """
    from core.vlan_utils import vlan_requires_password
    if not device.assigned_vlan:
        return False
    if device.current_vlan != device.assigned_vlan:
        return False
    if vlan_requires_password(device.assigned_vlan) and not device.ownership_validated:
        return False
    return True


def normalize_device_status(device: Device) -> Device:
    """Normalise legacy registration_status values to current canonical values."""
    if not device:
        return device
    updated = False
    if device.registration_status in {'active', 'approved'}:
        device.registration_status = 'registered'
        updated = True
    elif device.registration_status == 'restricted':
        device.registration_status = 'blocked'
        updated = True
    if updated:
        db.session.commit()
    return device


# ---------------------------------------------------------------------------
# UnregisteredLease helpers
# ---------------------------------------------------------------------------

def upsert_unregistered_lease(mac_address: str, ip_address: str,
                               expires_at, commit: bool = True) -> None:
    if not mac_address or not ip_address or not expires_at:
        return
    lease = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
    if lease:
        lease.ip_address = ip_address
        lease.expires_at = expires_at
    else:
        lease = UnregisteredLease(
            mac_address=mac_address,
            ip_address=ip_address,
            expires_at=expires_at,
        )
        db.session.add(lease)
    if commit:
        db.session.commit()


def clear_unregistered_lease(mac_address: str) -> None:
    if not mac_address:
        return
    lease = UnregisteredLease.query.filter_by(mac_address=mac_address).first()
    if lease:
        db.session.delete(lease)
        db.session.commit()


# ---------------------------------------------------------------------------
# Lease expiry helper
# ---------------------------------------------------------------------------

def get_lease_expiry_for_mac(mac_address: str, subnet_id=None):
    """Return the lease expiry datetime for a MAC address via Kea, or None."""
    kea_socket = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
    try:
        from kea_integration import get_kea_client
        kea = get_kea_client(control_socket=kea_socket)
        if not kea:
            return None
        lease = kea.get_lease_by_mac(mac_address, subnet_id=subnet_id)
        if not lease:
            return None
        if lease.get("expire"):
            return datetime.utcfromtimestamp(int(lease["expire"]))
        cltt = lease.get("cltt")
        valid_lft = lease.get("valid-lft")
        if cltt and valid_lft:
            return datetime.utcfromtimestamp(int(cltt) + int(valid_lft))
    except Exception as exc:
        logger.warning("get_lease_expiry_for_mac %s: %s", mac_address, exc)
    return None


# ---------------------------------------------------------------------------
# Device unregistration (shared by multiple flows)
# ---------------------------------------------------------------------------

def unregister_device(device: Device, commit: bool = True) -> None:
    """
    Fully unregister a device per spec:
    - Cut off internet access for the remainder of the current lease
    - Remove Kea / RADIUS reservation
    - Close ownership history
    - Clear all Table-6 ownership fields
    - Notify central
    """
    from core.network import manage_dns_hijack, manage_switch_acl
    from core.vlan_utils import is_blocked_pool_ip
    from radius_coa import send_coa_disconnect
    import central_client

    mac_address = device.mac_address
    ip_address = device.ip_address
    vlan_id = device.current_vlan

    # Apply ACL block + DNS hijack for the remainder of the current lease
    if ip_address and not is_blocked_pool_ip(ip_address):
        lease_expiry = get_lease_expiry_for_mac(mac_address, subnet_id=vlan_id)
        if lease_expiry and lease_expiry > datetime.utcnow():
            if vlan_id:
                manage_switch_acl('block', ip_address, vlan_id)
            manage_dns_hijack('hijack', ip_address)
            upsert_iplease(
                mac_address=mac_address, ip_address=ip_address, vlan_id=vlan_id,
                lease_start=datetime.utcnow(), lease_expiry=lease_expiry,
                from_blocked_pool=False, dns_hijacked=True,
            )
            logger.info("unregister_device: blocked %s at %s until %s",
                        mac_address, ip_address, lease_expiry)

    # Remove Kea reservation / send RADIUS disconnect
    kea_socket = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
    if device.connection_type == 'wifi' and device.internet_accessible:
        try:
            from kea_integration import get_kea_client
            kea = get_kea_client(control_socket=kea_socket)
            if kea and vlan_id:
                if not kea.unregister_mac(mac=mac_address, vlan=vlan_id):
                    logger.warning("unregister_device: Kea unregister failed for %s", mac_address)
        except Exception as exc:
            logger.warning("unregister_device: Kea error for %s: %s", mac_address, exc)
    elif device.connection_type == 'wired':
        send_coa_disconnect(mac_address)

    # Close ownership history record
    close_ownership(mac_address, commit=False)

    # Clear all ownership/registration fields; device row is kept for audit
    device.device_name = None
    device.assigned_vlan = None
    device.internet_accessible = None
    device.internet_blocked = None
    device.ownership_validated = None
    device.unregister_token = None
    device.profile_snapshot = None
    device.confirmation_confirmed_at = None
    device.confirmation_deadline = None
    sync_registration_status(device)

    central_client.queue_device_unregistered(mac_address)

    if commit:
        db.session.commit()
        from core.network import cleanup_orphan_hijack_rules
        cleanup_orphan_hijack_rules()


# ---------------------------------------------------------------------------
# Test data reset
# ---------------------------------------------------------------------------

def reset_test_data() -> None:
    """
    Remove all users/devices/requests, Kea host/lease data, and NAT/DNS logs.
    Synchronous DB work only — Kea container restart is the caller's responsibility.
    """
    from models import CentralOutboundEvent

    kea_socket = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
    kea = None
    if os.path.exists(kea_socket):
        try:
            from kea_integration import get_kea_client
            kea = get_kea_client(control_socket=kea_socket)
        except Exception:
            pass
    else:
        logger.warning("Kea control socket missing, skipping reservation cleanup")

    devices = Device.query.all()
    if kea and devices:
        for device in devices:
            vlan_id = device.wired_target_vlan or device.current_vlan
            if not vlan_id:
                continue
            try:
                kea.unregister_mac(device.mac_address, vlan_id)
            except Exception as exc:
                logger.warning("Kea unregister failed for %s vlan %s: %s",
                               device.mac_address, vlan_id, exc)

    db.session.query(RegistrationRequest).delete(synchronize_session=False)
    db.session.query(DeviceOwnership).delete(synchronize_session=False)
    db.session.query(IPLease).delete(synchronize_session=False)
    db.session.query(Device).delete(synchronize_session=False)
    db.session.query(User).delete(synchronize_session=False)
    db.session.query(UnregisteredLease).delete(synchronize_session=False)
    db.session.commit()

    db.session.execute(text("DELETE FROM hosts"))
    db.session.execute(text("DELETE FROM lease4"))
    db.session.execute(text("DELETE FROM nat_sessions"))
    db.session.execute(text("DELETE FROM dns_resolutions"))
    db.session.execute(text("DELETE FROM mac_port_cache"))
    db.session.execute(text("DELETE FROM central_outbound_events"))
    db.session.commit()

    lease_file = '/kea/leases/kea-leases4.csv'
    try:
        with open(lease_file, 'w') as _f:
            _f.write(
                'address,hwaddr,client_id,valid_lifetime,expire,'
                'subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n'
            )
        logger.info("Kea CSV lease file truncated: %s", lease_file)
    except Exception as exc:
        logger.warning("Failed to truncate Kea lease file %s: %s", lease_file, exc)
