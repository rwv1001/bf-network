"""
Network enforcement helpers.

Covers:
- DNS hijack management (iptables)
- HP5130 ACL block/unblock
- ACL baseline reset
- Inter-VLAN isolation ACL push
- Orphan hijack rule cleanup
- apply_device_block() / apply_device_unblock()
- reapply_all_ip_blocks()
- replug_switch_port_for_mac()
- clear_mac_auth_sessions(), reset_user_ports()
- reset_vlan_interface_masks(), reset_pi_network_masks()
- reset_acl_queue_files()
"""

import ipaddress
import logging
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime

from extensions import db

logger = logging.getLogger(__name__)


def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')


def _get_iptables_base_cmd() -> list:
    if os.geteuid() == 0:
        return ["iptables"]
    if shutil.which("sudo"):
        return ["sudo", "iptables"]
    return ["iptables"]


# ---------------------------------------------------------------------------
# DNS hijack
# ---------------------------------------------------------------------------

def manage_dns_hijack(action: str, ip_address: str) -> bool:
    """
    Manage DNS hijacking for a device IP.
    action: 'hijack' to enable DNS redirect, 'unhijack' to remove it.
    """
    script_path = '/scripts/dns-hijack.sh'
    try:
        result = subprocess.run(
            [script_path, action, ip_address],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            logger.info("DNS %s successful for %s: %s", action, ip_address, result.stdout.strip())
            return True
        logger.error("DNS %s failed for %s: %s", action, ip_address, result.stderr.strip())
        return False
    except subprocess.TimeoutExpired:
        logger.error("DNS %s timed out for %s", action, ip_address)
        return False
    except Exception as exc:
        logger.error("DNS %s error for %s: %s", action, ip_address, exc)
        return False


def reset_dns_hijack_rules() -> bool:
    """Remove all per-IP hijack rules and restore blocked pool ranges."""
    base_cmd = _get_iptables_base_cmd()
    result = subprocess.run(
        base_cmd + ["-t", "nat", "-S", "PREROUTING"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        logger.error("Failed to read iptables rules: %s", result.stderr.strip())
        return False

    hijack_dns_ip = os.environ.get('HIJACK_DNS_IP', '')
    portal_ip = os.environ.get('PORTAL_IP', '')

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("-A PREROUTING"):
            continue
        if "DNAT" not in line:
            continue
        if (
            f"--to-destination {hijack_dns_ip}:53" not in line
            and f"--to-destination {portal_ip}:8080" not in line
        ):
            continue
        delete_parts = shlex.split(line)
        delete_parts[0] = "-D"
        delete_cmd = base_cmd + ["-t", "nat"] + delete_parts
        subprocess.run(delete_cmd, capture_output=True, text=True, timeout=15)

    script_path = '/scripts/dns-hijack.sh'
    subprocess.run([script_path, "hijack-blocked-pools"],
                   capture_output=True, text=True, timeout=15)
    return True


# ---------------------------------------------------------------------------
# HP5130 ACL management
# ---------------------------------------------------------------------------

def manage_switch_acl(action: str, ip_address: str, vlan_id) -> bool:
    """
    Manage HP5130 ACL rules for blocking/unblocking specific IPs.

    block:   targets only the ISP router's switch for the VLAN.
    unblock: targets ALL switches to remove any stale rules.
    """
    from core.switch import get_switch_hosts, get_switch_host_for_vlan, run_switch_command

    if not vlan_id and ip_address:
        try:
            vlan_id = int(ip_address.split('.')[2])
        except (IndexError, ValueError):
            vlan_id = None

    if not vlan_id:
        logger.error("Unable to determine VLAN ID for ACL update")
        return False

    all_switch_hosts = get_switch_hosts()
    if not all_switch_hosts:
        logger.error("manage_switch_acl: no SWITCH_HOSTS configured")
        return False

    if action == 'block':
        isp_switch = get_switch_host_for_vlan(vlan_id)
        if isp_switch:
            switch_hosts = [isp_switch]
        else:
            switch_hosts = all_switch_hosts
            logger.warning(
                "manage_switch_acl block: ISP router switch not found for VLAN %s,"
                " falling back to all switches", vlan_id,
            )
    else:
        switch_hosts = all_switch_hosts

    try:
        host_octet = int(ip_address.split('.')[3])
    except (IndexError, ValueError):
        logger.error("Unable to determine host octet for ACL rule")
        return False

    rule_num = vlan_id * 150 + host_octet

    acl_script = os.getenv('ACL_QUEUE_SCRIPT', '/scripts/hp5130-acl.sh')
    use_acl_script = os.getenv('USE_ACL_QUEUE', '1') != '0'

    all_ok = True
    for switch_host in switch_hosts:
        if use_acl_script and os.path.isfile(acl_script):
            try:
                env = os.environ.copy()
                env['SWITCH_HOSTS'] = switch_host
                result = subprocess.run(
                    [acl_script, action, ip_address],
                    capture_output=True, text=True, timeout=15, env=env,
                )
                if result.returncode == 0:
                    logger.info("ACL %s queued for %s on %s via %s",
                                action, ip_address, switch_host, acl_script)
                    continue
                logger.warning("ACL queue script failed for %s on %s: %s",
                               ip_address, switch_host,
                               (result.stderr or result.stdout).strip())
            except Exception as exc:
                logger.warning("ACL queue script error for %s on %s: %s",
                               ip_address, switch_host, exc)

        # Fallback: apply directly via SSH
        if action == 'block':
            commands = [
                "system-view",
                "acl advanced 3951",
                f"rule {rule_num} deny ip source {ip_address} 0",
                "quit",
                "acl advanced 3953",
                f"rule {rule_num} deny ip source {ip_address} 0",
                "quit", "quit", "save force",
            ]
        elif action == 'unblock':
            commands = [
                "system-view",
                "acl advanced 3951",
                f"undo rule {rule_num}",
                "quit",
                "acl advanced 3953",
                f"undo rule {rule_num}",
                "quit", "quit", "save force",
            ]
        else:
            logger.error("Invalid action: %s", action)
            return False

        output = run_switch_command(switch_host, '\n'.join(commands))
        if output is None:
            logger.error("Switch ACL %s failed for %s on %s: no response",
                         action, ip_address, switch_host)
            all_ok = False

    return all_ok


def reset_acl_baseline() -> bool:
    """Re-apply baseline walled-garden ACLs on ALL configured switches."""
    from core.switch import get_switch_hosts
    script_path = os.getenv('ACL_BASELINE_SCRIPT', '/scripts/hp5130-acl-baseline.sh')
    if not os.path.isfile(script_path):
        logger.error("ACL baseline script not found: %s", script_path)
        return False

    switch_hosts = get_switch_hosts()
    if not switch_hosts:
        logger.error("reset_acl_baseline: no SWITCH_HOSTS configured")
        return False

    all_ok = True
    for host in switch_hosts:
        env = os.environ.copy()
        env['SWITCH_HOSTS'] = host
        if not env.get("SWITCH_KEY_PATH"):
            env["SWITCH_KEY_PATH"] = "/keys/id_rsa"

        result = subprocess.run([script_path], capture_output=True, text=True,
                                timeout=120, env=env)
        if result.returncode != 0:
            logger.error(
                "ACL baseline failed for %s (exit=%s). stderr=%s stdout=%s",
                host, result.returncode,
                (result.stderr or '').strip() or '<empty>',
                (result.stdout or '').strip() or '<empty>',
            )
            all_ok = False
        else:
            logger.info("ACL baseline pushed to %s", host)
            if not _push_vlan_isolation_acls(host):
                logger.warning("Inter-VLAN isolation ACLs failed for %s", host)
                all_ok = False
    return all_ok


def _push_vlan_isolation_acls(switch_host: str) -> bool:
    """Insert per-VLAN inter-VLAN deny rules into each VLAN's walled-garden ACL."""
    from core.switch import run_switch_command
    from core.vlan_utils import (
        WIRED_UNREGISTERED_STATUS, get_vlan_prefix_map, pool_bounds_for_prefix,
    )
    from models import VlanMapping

    try:
        vlans = VlanMapping.query.filter(
            VlanMapping.status != WIRED_UNREGISTERED_STATUS
        ).all()
    except Exception as exc:
        logger.warning('_push_vlan_isolation_acls: DB query failed: %s', exc)
        return True

    if not vlans:
        return True

    prefix_by_status = get_vlan_prefix_map()
    prefix_by_id = {}
    for v in vlans:
        try:
            prefix_by_id[v.vlan_id] = int(prefix_by_status.get(v.status, 24))
        except (TypeError, ValueError):
            prefix_by_id[v.vlan_id] = 24

    all_vlan_ids = set(prefix_by_id.keys())
    net_word = _net_word()

    lines = ['system-view']
    has_rules = False

    for v in sorted(vlans, key=lambda x: x.vlan_id):
        visible_ids = set()
        if v.visible_vlans:
            for part in v.visible_vlans.split(','):
                part = part.strip()
                if part.isdigit():
                    visible_ids.add(int(part))

        denied_vids = sorted(all_vlan_ids - visible_ids - {v.vlan_id})
        if not denied_vids:
            continue

        acl_num = 3000 + v.vlan_id * 10
        outbound_acl_num = acl_num + 1

        denied_nets = []
        for dvid in denied_vids:
            pfx = prefix_by_id.get(dvid, 24)
            try:
                net = ipaddress.ip_network(f'{net_word}.{dvid}.0/{pfx}', strict=False)
                denied_nets.append((net.network_address, net.hostmask))
            except ValueError:
                continue

        if not denied_nets:
            continue

        lines.append(f'acl advanced {acl_num}')
        rule_num = 25000
        for net_addr, hostmask in denied_nets:
            lines.append(f'rule {rule_num} deny ip destination {net_addr} {hostmask}')
            rule_num += 10
        lines.append('quit')

        lines.append(f'undo acl advanced {outbound_acl_num}')
        lines.append(f'acl advanced {outbound_acl_num}')
        lines.append(f'description "VLAN{v.vlan_id} Outbound Isolation"')
        rule_num = 25000
        for net_addr, hostmask in denied_nets:
            lines.append(f'rule {rule_num} deny ip source {net_addr} {hostmask}')
            rule_num += 10
        lines.append('rule 30000 permit ip')
        lines.append('quit')

        lines.append(f'interface Vlan-interface{v.vlan_id}')
        lines.append(f'packet-filter {outbound_acl_num} outbound')
        lines.append('quit')

        has_rules = True

    if not has_rules:
        return True

    lines.append('quit')
    lines.append('save force')
    command = '\n'.join(lines)

    out = run_switch_command(switch_host, command, timeout=300)
    if out is None:
        logger.warning('_push_vlan_isolation_acls: SSH command failed for %s', switch_host)
        return False
    logger.info('_push_vlan_isolation_acls: inter-VLAN deny rules pushed to %s', switch_host)
    return True


# ---------------------------------------------------------------------------
# Orphan hijack cleanup
# ---------------------------------------------------------------------------

def cleanup_orphan_hijack_rules() -> int:
    """Remove DNS/portal DNAT rules for IPs not assigned to any active device."""
    from models import IPLease, UnregisteredLease
    from core.vlan_utils import is_blocked_pool_ip

    hijack_dns_ip = os.environ.get('HIJACK_DNS_IP', '')
    portal_ip = os.environ.get('PORTAL_IP', '')

    try:
        now = datetime.utcnow()
        active_ips = {
            lease.ip_address
            for lease in IPLease.query.filter(
                IPLease.ip_address.isnot(None),
                IPLease.lease_expiry > now,
            ).all()
            if lease.ip_address
        }
        active_unregistered_ips = {
            lease.ip_address
            for lease in UnregisteredLease.query.filter(
                UnregisteredLease.ip_address.isnot(None)
            ).all()
            if lease.ip_address and (not lease.expires_at or lease.expires_at >= now)
        }
        active_ips |= active_unregistered_ips
    except Exception as exc:
        logger.error("Failed to load device IPs for cleanup: %s", exc)
        return 0

    base_cmd = _get_iptables_base_cmd()
    result = subprocess.run(
        base_cmd + ["-t", "nat", "-S", "PREROUTING"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        logger.error("Failed to read iptables rules: %s", result.stderr.strip())
        return 0

    removed = 0
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("-A PREROUTING"):
            continue
        if "DNAT" not in line:
            continue
        if (
            f"--to-destination {hijack_dns_ip}:53" not in line
            and f"--to-destination {portal_ip}:8080" not in line
        ):
            continue

        match = re.search(r"-s (\d+\.\d+\.\d+\.\d+)/32", line)
        if not match:
            continue

        ip_address = match.group(1)
        if ip_address in active_ips:
            continue
        if is_blocked_pool_ip(ip_address):
            continue

        delete_parts = shlex.split(line)
        delete_parts[0] = "-D"
        delete_cmd = base_cmd + ["-t", "nat"] + delete_parts
        delete_result = subprocess.run(
            delete_cmd, capture_output=True, text=True, timeout=15,
        )
        if delete_result.returncode == 0:
            removed += 1
            logger.info("Removed orphan DNAT rule for %s", ip_address)
        else:
            logger.warning("Failed to remove orphan DNAT rule for %s: %s",
                           ip_address, delete_result.stderr.strip())

    return removed


# ---------------------------------------------------------------------------
# Device block / unblock (spec B / C)
# ---------------------------------------------------------------------------

def apply_device_block(device, flash_messages: bool = False,
                       notify_central: bool = True) -> None:
    """
    Block a device per spec B/C:
    - set internet_blocked=True, internet_accessible=null
    - apply DNS hijack and ACL block to the device's current IP
    - ask Kea to flag the MAC for the blocked pool
    """
    from core.device_utils import (
        set_internet_blocked, clear_unregistered_lease, get_active_iplease,
    )
    from core.vlan_utils import is_blocked_pool_ip
    from kea_integration import get_kea_client
    import central_client

    set_internet_blocked(device, True, commit=False)
    db.session.commit()
    clear_unregistered_lease(device.mac_address)

    kea_socket = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
    kea = None
    try:
        kea = get_kea_client(control_socket=kea_socket)
    except Exception:
        pass

    block_ip = device.ip_address
    if kea and device.current_vlan:
        if not block_ip:
            block_ip = kea.get_lease_ip_for_mac(
                device.mac_address, subnet_id=device.current_vlan
            )
        kea.set_block_status(device.mac_address, device.current_vlan, True,
                             blocked_ip=block_ip)
        if block_ip:
            kea.force_lease_renewal(device.mac_address, block_ip)

    if block_ip and device.current_vlan:
        acl_success = True
        if not is_blocked_pool_ip(block_ip):
            manage_dns_hijack('hijack', block_ip)
            acl_success = manage_switch_acl('block', block_ip, device.current_vlan)
            lease = get_active_iplease(device.mac_address)
            if lease:
                lease.dns_hijacked = True
                db.session.commit()
        if flash_messages:
            from flask import flash
            if acl_success:
                flash(f'Device {device.mac_address} blocked. Internet access denied.', 'success')
            else:
                flash(f'Device {device.mac_address} marked as blocked, but ACL update failed.',
                      'warning')
        logger.info("Blocked device %s at %s (acl_success=%s)",
                    device.mac_address, block_ip, acl_success)
    else:
        if flash_messages:
            from flask import flash
            flash(f'Device {device.mac_address} marked as blocked (no active IP found).', 'warning')
        logger.warning("Block: no IP/VLAN for device %s", device.mac_address)

    cleanup_orphan_hijack_rules()
    if notify_central:
        central_client.queue_device_blocked(device)


def apply_device_unblock(device, flash_messages: bool = False,
                         notify_central: bool = True) -> None:
    """
    Unblock a device per spec B/C:
    - clear internet_blocked
    - remove DNS hijack and ACL block if conditions are met
    - set internet_accessible=True if eligible
    """
    from core.device_utils import (
        set_internet_blocked, set_internet_accessible, clear_unregistered_lease,
        get_active_iplease, should_have_internet, get_active_ownership,
    )
    from core.vlan_utils import is_blocked_pool_ip
    from kea_integration import get_kea_client
    import central_client
    from models import RegistrationRequest

    # Accept the device on its current VLAN
    if device.current_vlan and get_active_ownership(device.mac_address):
        if not device.assigned_vlan or device.assigned_vlan != device.current_vlan:
            device.assigned_vlan = device.current_vlan

    set_internet_blocked(device, None, commit=False)
    db.session.commit()
    clear_unregistered_lease(device.mac_address)

    kea_socket = os.getenv('KEA_CONTROL_SOCKET', '/kea/leases/kea4-ctrl-socket')
    kea = None
    try:
        kea = get_kea_client(control_socket=kea_socket)
    except Exception:
        pass

    blocked_ip = None
    if kea and device.current_vlan:
        blocked_ip = kea.get_blocked_ip_from_reservation(device.mac_address, device.current_vlan)
        kea.set_block_status(device.mac_address, device.current_vlan, False)

    lease = get_active_iplease(device.mac_address)
    ip_in_blocked_pool = (
        is_blocked_pool_ip(device.ip_address) or
        (lease and lease.from_blocked_pool)
    )

    if should_have_internet(device) and not ip_in_blocked_pool:
        acl_success = True
        if device.ip_address and device.current_vlan:
            manage_dns_hijack('unhijack', device.ip_address)
            acl_success = manage_switch_acl('unblock', device.ip_address, device.current_vlan)
            if blocked_ip and blocked_ip != device.ip_address:
                manage_switch_acl('unblock', blocked_ip, device.current_vlan)
                manage_dns_hijack('unhijack', blocked_ip)
            if lease:
                lease.dns_hijacked = False
                db.session.commit()
        set_internet_accessible(device, True, commit=True)
        if flash_messages:
            from flask import flash
            if acl_success:
                flash(f'Device {device.mac_address} unblocked. Internet access restored.',
                      'success')
            else:
                flash(f'Device {device.mac_address} unblocked, but ACL removal failed.',
                      'warning')
        logger.info("Unblocked device %s at %s", device.mac_address, device.ip_address)
    else:
        if blocked_ip and device.current_vlan:
            manage_dns_hijack('unhijack', blocked_ip)
            manage_switch_acl('unblock', blocked_ip, device.current_vlan)
        if (device.ip_address and device.current_vlan
                and not is_blocked_pool_ip(device.ip_address)
                and device.ip_address != blocked_ip):
            manage_dns_hijack('unhijack', device.ip_address)
            manage_switch_acl('unblock', device.ip_address, device.current_vlan)
        set_internet_accessible(device, False if device.assigned_vlan else None, commit=True)
        if flash_messages:
            from flask import flash
            if ip_in_blocked_pool:
                flash(
                    f'Device {device.mac_address} unblocked. '
                    'It is in the blocked pool — disconnect and reconnect to regain access.',
                    'info',
                )
            else:
                flash(
                    f'Device {device.mac_address} unblocked, but it is on the wrong VLAN '
                    f'or still needs password validation.',
                    'info',
                )
        logger.info("Unblocked device %s: conditions not yet met for internet access",
                    device.mac_address)

    RegistrationRequest.query.filter_by(
        mac_address=device.mac_address, status='rejected'
    ).update(
        {'status': 'superseded', 'processed_at': datetime.utcnow(),
         'processed_by': 'superseded-by-admin-unblock'},
        synchronize_session=False,
    )
    db.session.commit()
    cleanup_orphan_hijack_rules()


# ---------------------------------------------------------------------------
# Reapply all IP blocks
# ---------------------------------------------------------------------------

def reapply_all_ip_blocks() -> tuple:
    """
    Re-push every current per-device IP block to all switches.
    Returns (pushed_count, failed_count).
    """
    from models import IPLease, Device
    now = datetime.utcnow()
    pushed = 0
    failed = 0

    leases = IPLease.query.filter(
        IPLease.lease_expiry > now,
        IPLease.from_blocked_pool == False,  # noqa: E712
    ).all()

    for lease in leases:
        device = Device.query.filter_by(mac_address=lease.mac_address).first()
        if not device:
            continue
        if device.internet_accessible is True:
            continue
        vlan_id = lease.vlan_id or device.current_vlan
        if not vlan_id or not lease.ip_address:
            continue
        ok = manage_switch_acl('block', lease.ip_address, vlan_id)
        if ok:
            pushed += 1
        else:
            failed += 1
            logger.warning("reapply_all_ip_blocks: failed to block %s on VLAN %s",
                           lease.ip_address, vlan_id)

    logger.info("reapply_all_ip_blocks: pushed=%d failed=%d", pushed, failed)
    return pushed, failed


# ---------------------------------------------------------------------------
# Switch port replug
# ---------------------------------------------------------------------------

def replug_switch_port_for_mac(mac_address: str) -> bool:
    """Bounce the switch port for a MAC address to force re-authentication."""
    import time
    from core.switch import (
        find_switch_port_for_mac, persist_switch_port,
        switch_port_allowed, run_switch_command, expand_switch_iface_name,
    )

    def _env_truthy(name, default=False):
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {'1', 'true', 'yes', 'on'}

    if not _env_truthy('SWITCH_REPLUG_ENABLED', False):
        logger.info("Switch replug disabled; skipping for %s", mac_address)
        return False

    replug_script = os.getenv('SWITCH_REPLUG_SCRIPT', '/scripts/hp5130-replug.sh')
    if os.path.isfile(replug_script):
        try:
            delay = os.getenv('SWITCH_REPLUG_DELAY_SEC', '3')
            result = subprocess.run(
                [replug_script, mac_address, delay],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                logger.info("Replug script succeeded for %s", mac_address)
                return True
            logger.warning("Replug script failed for %s: %s",
                           mac_address, (result.stderr or result.stdout).strip())
        except Exception as exc:
            logger.warning("Replug script error for %s: %s", mac_address, exc)

    result = find_switch_port_for_mac(mac_address)
    if not result:
        logger.warning("Unable to locate switch port for %s", mac_address)
        return False
    switch_host, port = result
    if not switch_port_allowed(port):
        logger.warning("Switch replug blocked for port %s", port)
        return False

    persist_switch_port(mac_address, port, switch_host)

    delay_raw = os.getenv('SWITCH_REPLUG_DELAY_SEC', '3')
    try:
        delay_sec = max(1, int(delay_raw))
    except ValueError:
        delay_sec = 3

    expanded = expand_switch_iface_name(port)
    cmds_down = f"system-view\ninterface {expanded}\nshutdown\nquit\nquit"
    cmds_up   = f"system-view\ninterface {expanded}\nundo shutdown\nquit\nquit"

    run_switch_command(switch_host, cmds_down)
    time.sleep(delay_sec)
    run_switch_command(switch_host, cmds_up)
    logger.info("Replug complete for %s on port %s", mac_address, port)
    return True


# ---------------------------------------------------------------------------
# MAC auth / port reset / VLAN interface / Pi network helpers
# ---------------------------------------------------------------------------

def clear_mac_auth_sessions() -> bool:
    script_path = os.getenv('CLEAR_MAC_AUTH_SCRIPT', '/scripts/hp5130-clear-mac-auth.sh')
    if not os.path.isfile(script_path):
        logger.warning("MAC auth clear script not found: %s", script_path)
        return False
    env = os.environ.copy()
    if not env.get("SWITCH_KEY_PATH"):
        env["SWITCH_KEY_PATH"] = "/keys/id_rsa"
    result = subprocess.run([script_path], capture_output=True, text=True, timeout=60, env=env)
    if result.returncode != 0:
        logger.error("MAC auth clear failed (exit=%s). stderr=%s stdout=%s",
                     result.returncode,
                     (result.stderr or '').strip() or '<empty>',
                     (result.stdout or '').strip() or '<empty>')
        return False
    return True


def reset_user_ports() -> bool:
    script_path = os.getenv('RESET_USER_PORTS_SCRIPT', '/scripts/hp5130-reset-user-ports.sh')
    if not os.path.isfile(script_path):
        logger.warning("Reset user ports script not found: %s", script_path)
        return False
    env = os.environ.copy()
    if not env.get("SWITCH_KEY_PATH"):
        env["SWITCH_KEY_PATH"] = "/keys/id_rsa"
    result = subprocess.run([script_path], capture_output=True, text=True, timeout=120, env=env)
    if result.returncode != 0:
        logger.error("Reset user ports failed (exit=%s). stderr=%s stdout=%s",
                     result.returncode,
                     (result.stderr or '').strip() or '<empty>',
                     (result.stdout or '').strip() or '<empty>')
        return False
    return True


def reset_vlan_interface_masks(vlan_ids: list) -> bool:
    vlan_ids = [str(v) for v in vlan_ids if v]
    if not vlan_ids:
        return True
    script_path = os.getenv('VLAN_INTERFACE_SCRIPT', '/scripts/hp5130-vlan-interface.sh')
    if not os.path.isfile(script_path):
        logger.error("VLAN interface script not found: %s", script_path)
        return False
    env = os.environ.copy()
    if not env.get("SWITCH_KEY_PATH"):
        env["SWITCH_KEY_PATH"] = "/keys/id_rsa"
    env["VLAN_LIST"] = " ".join(vlan_ids)
    env["SWITCH_HOSTS"] = os.getenv('SWITCH_HOSTS', '')
    result = subprocess.run([script_path], capture_output=True, text=True, timeout=120, env=env)
    if result.returncode != 0:
        logger.error("VLAN interface update failed (exit=%s). stderr=%s stdout=%s",
                     result.returncode,
                     (result.stderr or '').strip() or '<empty>',
                     (result.stdout or '').strip() or '<empty>')
        return False
    return True


def reset_pi_network_masks(vlan_ids: list) -> bool:
    vlan_ids = [str(v) for v in vlan_ids if v]
    if not vlan_ids:
        return True
    script_path = os.getenv('PI_NETWORK_SCRIPT', '/scripts/pi-network-update.sh')
    if not os.path.isfile(script_path):
        logger.error("Pi network script not found: %s", script_path)
        return False
    env = os.environ.copy()
    env["VLAN_LIST"] = " ".join(vlan_ids)
    if env.get("PI_NETWORK_DIR"):
        env["NETWORK_DIR"] = env["PI_NETWORK_DIR"]
    result = subprocess.run([script_path], capture_output=True, text=True, timeout=120, env=env)
    if result.returncode != 0:
        logger.error("Pi network update failed (exit=%s). stderr=%s stdout=%s",
                     result.returncode,
                     (result.stderr or '').strip() or '<empty>',
                     (result.stdout or '').strip() or '<empty>')
        return False
    return True


def reset_acl_queue_files() -> None:
    queue_base = os.getenv('ACL_QUEUE_DIR') or (
        '/acl-queue' if os.path.isdir('/acl-queue') else '/shared/acl-queue'
    )
    try:
        if os.path.isdir(queue_base):
            for name in os.listdir(queue_base):
                path = os.path.join(queue_base, name)
                is_dedup = name.startswith('.dedup-')
                is_acl_file = (
                    name.startswith('hp5130-acl') and
                    (name.endswith('.queue') or name.endswith('.pid') or name.endswith('.lock'))
                )
                is_acl_lock_dir = (
                    name.startswith('hp5130-acl') and
                    name.endswith('.lock') and
                    os.path.isdir(path)
                )
                if is_dedup or is_acl_file or is_acl_lock_dir:
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    else:
                        try:
                            os.remove(path)
                            logger.info("ACL queue file cleared: %s", path)
                        except FileNotFoundError:
                            pass
    except Exception as exc:
        logger.warning("Failed to clear ACL queue files: %s", exc)
