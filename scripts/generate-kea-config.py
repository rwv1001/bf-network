#!/usr/bin/env python3
"""
Generate dhcp4.json for Kea DHCP4 from environment variables.

Pool bounds for regular VLANs are computed from VLAN_PREFIX_MAP so the config
stays correct when subnet sizes change, with no hardcoded IP ranges.

Special subnets:
  WIRED_VLAN      (default 250) – unregistered wired clients (single pool,
                                   hijack DNS, separate gateway)
  MANAGEMENT_VLAN (default 99)  – management / infrastructure (static range
                                   .100-.254, public DNS)

Environment variables
---------------------
WIRED_VLAN              VLAN ID for wired-unregistered devices (default: 250)
MANAGEMENT_VLAN         VLAN ID for management / switch hosts (default: 99)
UNREGISTERED_GW_BYTE    Last octet of the unregistered gateway IP (default: 2)
                        Gateway = NETWORK_WORD.MANAGEMENT_VLAN.<byte>
                        e.g. 192.168.99.2
                        Falls back to legacy UNREGISTERED_GW env var if set.
SWITCH_HOSTS_BYTES      Comma-separated last octets of switch management IPs
                        (default: 2).  First entry is used as the management
                        VLAN gateway.
                        Falls back to legacy SWITCH_HOSTS env var if set.
"""

import ipaddress
import json
import os
import sys


def require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        print(f"ERROR: {name} is required but not set", file=sys.stderr)
        sys.exit(1)
    return val


def parse_vlan_prefix_map(raw: str) -> dict:
    result = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        vlan_str, prefix_str = entry.split(":", 1)
        try:
            result[int(vlan_str.strip())] = int(prefix_str.strip())
        except ValueError:
            continue
    return result


def pool_bounds(prefix: int) -> dict:
    total = 2 ** (32 - prefix)
    block_size = 40 * (2 ** (24 - prefix))
    registered_end = total - block_size - 1
    return {
        "registered_start": 1,
        "registered_end": registered_end,
        "blocked_start": registered_end + 1,
        "blocked_end": total - 1,
    }


def ip_at_offset(network: ipaddress.IPv4Network, offset: int) -> str:
    return str(ipaddress.IPv4Address(int(network.network_address) + offset))


def _get_wired_vlan() -> int:
    """Return the wired-unregistered VLAN ID (WIRED_VLAN env var, default 250)."""
    try:
        return int(os.environ.get("WIRED_VLAN", "250"))
    except (TypeError, ValueError):
        return 250


def _get_management_vlan() -> int:
    """Return the management VLAN ID (MANAGEMENT_VLAN env var, default 99)."""
    try:
        return int(os.environ.get("MANAGEMENT_VLAN", "99"))
    except (TypeError, ValueError):
        return 99


def _get_switch_host_ips(network_word: str) -> list:
    """
    Return the list of switch management IP addresses.

    Resolution order:
    1. SWITCH_HOSTS_BYTES (comma-separated last octets) combined with
       NETWORK_WORD and MANAGEMENT_VLAN.
    2. Legacy SWITCH_HOSTS env var (space-separated full IPs).
    """
    bytes_raw = os.environ.get("SWITCH_HOSTS_BYTES", "").strip()
    if bytes_raw:
        mgmt_vlan = _get_management_vlan()
        hosts = []
        for part in bytes_raw.split(","):
            part = part.strip()
            if part.isdigit():
                hosts.append(f"{network_word}.{mgmt_vlan}.{part}")
        if hosts:
            return hosts

    legacy = os.environ.get("SWITCH_HOSTS", "").strip()
    if legacy:
        return [h.strip() for h in legacy.split() if h.strip()]

    return []


def _get_unregistered_gw(network_word: str) -> str:
    """
    Return the unregistered-network gateway IP.

    Derived from NETWORK_WORD + MANAGEMENT_VLAN + UNREGISTERED_GW_BYTE.
    Falls back to the legacy UNREGISTERED_GW env var if set.
    """
    legacy = os.environ.get("UNREGISTERED_GW", "").strip()
    if legacy:
        return legacy
    try:
        gw_byte = int(os.environ.get("UNREGISTERED_GW_BYTE", "2"))
    except (TypeError, ValueError):
        gw_byte = 2
    mgmt_vlan = _get_management_vlan()
    return f"{network_word}.{mgmt_vlan}.{gw_byte}"


def infra_ghost_reservations(network_word: str, vlan: int, switch_hosts_raw: str) -> list:
    """Reserve infra + every switch last-octet on this VLAN."""
    host_octets = {1, 2, 3, 4, 5}

    print(
        f"DEBUG infra_ghost: vlan={vlan} network_word={network_word!r} "
        f"switch_hosts_raw={switch_hosts_raw!r}",
        file=sys.stderr,
    )

    for host_str in switch_hosts_raw.split():
        host_str = host_str.strip()
        if not host_str:
            continue
        try:
            parts = str(ipaddress.IPv4Address(host_str)).split(".")
            octet = int(parts[3])
            host_octets.add(octet)
            print(
                f"DEBUG infra_ghost: vlan={vlan} from host {host_str} → octet {octet}",
                file=sys.stderr,
            )
        except ValueError as e:
            print(
                f"DEBUG infra_ghost: skip host {host_str!r}: {e}",
                file=sys.stderr,
            )

    reservations = []
    for octet in sorted(host_octets):
        ghost_mac = f"02:00:c0:a8:{vlan & 0xff:02x}:{octet:02x}"
        ip = f"{network_word}.{vlan}.{octet}"
        reservations.append({
            "hw-address": ghost_mac,
            "ip-address": ip,
            "user-context": {"infra-ghost": True},
        })
        print(
            f"DEBUG infra_ghost: vlan={vlan} reservation {ip} mac={ghost_mac}",
            file=sys.stderr,
        )

    print(
        f"DEBUG infra_ghost: vlan={vlan} total reservations={len(reservations)} "
        f"octets={sorted(host_octets)}",
        file=sys.stderr,
    )
    return reservations


def make_vlan_subnet(
    network_word: str,
    vlan: int,
    prefix: int,
    switch_hosts_raw: str,
    gateway_octet: int,
) -> dict:
    network = ipaddress.IPv4Network(f"{network_word}.{vlan}.0/{prefix}", strict=False)
    bounds = pool_bounds(prefix)
    router = f"{network_word}.{vlan}.{gateway_octet}"
    return {
        "subnet": str(network),
        "id": vlan,
        "pools": [
            {
                "pool": (
                    f"{ip_at_offset(network, bounds['blocked_start'])}"
                    f" - "
                    f"{ip_at_offset(network, bounds['blocked_end'])}"
                ),
                "client-classes": ["BLOCKED"],
            },
            {
                "pool": (
                    f"{ip_at_offset(network, bounds['registered_start'])}"
                    f" - "
                    f"{ip_at_offset(network, bounds['registered_end'])}"
                ),
                "client-classes": ["NOT_BLOCKED"]
            },
        ],
        "interface": f"eth0.{vlan}",
        "option-data": [
            {"name": "routers", "data": router}
        ],
        "reservations": infra_ghost_reservations(network_word, vlan, switch_hosts_raw),
    }

def fetch_vlan_gateway_octets(
    db_host, db_port, db_name, db_user, db_password, fallback_octet
):
    """
    Build {vlan_id: gateway_octet} from vlan_mappings → isp_routers.switch_host.

    gateway_octet = last octet of isp_routers.switch_host for that VLAN's
    isp_router_id.  VLANs with no isp_router_id / empty switch_host are omitted
    so the caller can fall back to fallback_octet.
    """
    mapping = {}
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            dbname=db_name,
            user=db_user,
            password=db_password,
        )
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT vm.vlan_id, ir.switch_host
                      FROM vlan_mappings vm
                      LEFT JOIN isp_routers ir ON ir.id = vm.isp_router_id
                     WHERE vm.vlan_id IS NOT NULL
                    """
                )
                for vlan_id, switch_host in cur.fetchall():
                    if not switch_host:
                        continue
                    host = str(switch_host).strip()
                    try:
                        octet = int(host.rsplit(".", 1)[-1])
                    except (ValueError, IndexError):
                        continue
                    mapping[int(vlan_id)] = octet
        finally:
            conn.close()
    except Exception as e:
        print(
            f"WARNING: could not load vlan→ISP gateway map from DB ({e}); "
            f"using fallback octet {fallback_octet} for all VLANs",
            file=sys.stderr,
        )
    return mapping

def main():
    network_word = require_env("NETWORK_WORD")

    wired_vlan      = _get_wired_vlan()
    management_vlan = _get_management_vlan()

    # Prefer a prefix-map file written by the captive portal (kept up-to-date
    # when the admin changes subnet sizes via the UI) over the env var, which
    # only reflects what was set at container-build time.
    prefix_map_file = os.path.join(
        os.path.dirname(os.environ.get("KEA_CONFIG_PATH", "/kea/config/dhcp4.json")),
        "vlan-prefix-map.txt",
    )
    if os.path.isfile(prefix_map_file):
        with open(prefix_map_file, "r", encoding="utf-8") as _f:
            raw_prefix_map = _f.read().strip()
    else:
        raw_prefix_map = require_env("VLAN_PREFIX_MAP")

    vlan_prefix_map = parse_vlan_prefix_map(raw_prefix_map)
    if not vlan_prefix_map:
        print("ERROR: VLAN_PREFIX_MAP is empty or unparseable", file=sys.stderr)
        sys.exit(1)

    db_host     = require_env("DB_HOST")
    db_port     = int(require_env("DB_PORT"))
    db_name     = require_env("DB_NAME")
    db_user     = require_env("DB_USER")
    db_password = require_env("DB_PASSWORD")

    portal_ip     = require_env("PORTAL_IP")
    hijack_dns_ip = require_env("HIJACK_DNS_IP")

    # Derive switch hosts and gateway from new env vars (with legacy fallback)
    switch_host_ips  = _get_switch_host_ips(network_word)
    switch_hosts_raw = " ".join(switch_host_ips)
    if not switch_host_ips:
        print("ERROR: no switch hosts configured "
              "(set SWITCH_HOSTS_BYTES or SWITCH_HOSTS)", file=sys.stderr)
        sys.exit(1)
    # Fallback only when a VLAN has no isp_router_id / switch_host
    fallback_octet = int(
        str(ipaddress.IPv4Address(switch_host_ips[0])).split(".")[3]
    )
    # Management VLAN gateway stays on the first switch SVI
    mgmt_gateway = switch_host_ips[0]

    vlan_gw_octets = fetch_vlan_gateway_octets(
        db_host, db_port, db_name, db_user, db_password, fallback_octet
    )

    unregistered_gw = _get_unregistered_gw(network_word)

    # VLANs for wired-unregistered and management are handled by the explicit
    # blocks below with their own pool/DNS/gateway config — skip them here.
    SPECIAL_VLANS = {wired_vlan, management_vlan}
    subnet4 = []
    for vlan, prefix in sorted(vlan_prefix_map.items()):
        if vlan in SPECIAL_VLANS:
            continue
        # Prefer ISP-router switch_host last octet; else first switch
        gateway_octet = vlan_gw_octets.get(vlan, fallback_octet)
        subnet4.append(
            make_vlan_subnet(
                network_word, vlan, prefix, switch_hosts_raw, gateway_octet
            )
        )

    # Wired-unregistered clients — single pool, no blocked split, hijack DNS
    subnet4.append({
        "subnet": f"{network_word}.{wired_vlan}.0/24",
        "id": wired_vlan,
        "pools": [
            {"pool": f"{network_word}.{wired_vlan}.1 - {network_word}.{wired_vlan}.255"}
        ],
        "interface": f"eth0.{wired_vlan}",
        "option-data": [
            {"name": "routers",             "data": unregistered_gw},
            {"name": "domain-name-servers", "data": hijack_dns_ip},
        ],
        "reservations": infra_ghost_reservations(network_word, wired_vlan, switch_hosts_raw),
    })

    # Management VLAN — lower range reserved for static infra, public DNS
    subnet4.append({
        "subnet": f"{network_word}.{management_vlan}.0/24",
        "id": management_vlan,
        "pools": [
            {"pool": f"{network_word}.{management_vlan}.1 - {network_word}.{management_vlan}.254"}
        ],
        "interface": f"eth0.{management_vlan}",
        "option-data": [
            {"name": "routers",             "data": mgmt_gateway},
            {"name": "domain-name-servers", "data": "8.8.8.8, 8.8.4.4"},
        ],
        "reservations": infra_ghost_reservations(network_word, management_vlan, switch_hosts_raw),
    })

    interfaces = (
        [f"eth0.{v}" for v in sorted(vlan_prefix_map) if v not in SPECIAL_VLANS]
        + [f"eth0.{wired_vlan}", f"eth0.{management_vlan}"]
    )

    config = {
        "Dhcp4": {
            "authoritative": True,
            "interfaces-config": {
                "interfaces": interfaces,
                "dhcp-socket-type": "raw",
            },
            "multi-threading": {"enable-multi-threading": True},
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/kea/sockets/kea4-ctrl-socket",
            },
            "hooks-libraries": [
                {"library": "/usr/local/lib/kea/hooks/libdhcp_pgsql.so"},
                {"library": "/usr/local/lib/kea/hooks/libdhcp_host_cmds.so"},
                {"library": "/usr/local/lib/kea/hooks/libdhcp_lease_cmds.so"},
                {"library": "/usr/local/lib/kea/hooks/dhcp_dns_hijack.so"},
            ],
            "lease-database": {
                "type": "memfile",
                "persist": True,
                "name": "/kea/leases/kea-leases4.csv",
                "lfc-interval": 3600,
            },
            "hosts-database": {
                "type": "postgresql",
                "name": db_name,
                "user": db_user,
                "password": db_password,
                "host": db_host,
                "port": db_port,
                "max-reconnect-tries": 5,
                "reconnect-wait-time": 5,
            },
            "expired-leases-processing": {
                "reclaim-timer-wait-time": 10,
                "flush-reclaimed-timer-wait-time": 25,
                "hold-reclaimed-time": 3600,
                "max-reclaim-leases": 100,
                "max-reclaim-time": 250,
                "unwarned-reclaim-cycles": 5,
            },
            "renew-timer": int(os.environ.get("KEA_RENEW_TIMER", "300")),
            "rebind-timer": int(os.environ.get("KEA_REBIND_TIMER", "480")),
            "valid-lifetime": int(os.environ.get("KEA_VALID_LIFETIME", "600")),
            "option-data": [
                {"name": "domain-name",        "data": "blackfriars.local"},
                {"name": "domain-name-servers", "data": portal_ip},
            ],
            # Allow Kea to use global host reservations (dhcp4_subnet_id=0) for
            # client-class assignment (e.g. BLOCKED class set by central_import.py).
            "reservations-global": True,
            "client-classes": [
                {"name": "BLOCKED"},
                {"name": "NOT_BLOCKED", "test": "not member('BLOCKED')"}
            ],
            "subnet4": subnet4,
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output_options": [
                        {"output": "stdout", "pattern": "%-5p %m\n"}
                    ],
                    "severity": "INFO",
                    "debuglevel": 0,
                }
            ],
        }
    }

    print(json.dumps(config, indent=2))


if __name__ == "__main__":
    main()
