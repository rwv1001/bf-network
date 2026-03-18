#!/usr/bin/env python3
"""
Generate dhcp4.json for Kea DHCP4 from environment variables.

Pool bounds for regular VLANs are computed from VLAN_PREFIX_MAP so the config
stays correct when subnet sizes change, with no hardcoded IP ranges.

Special subnets:
  VLAN 250 – unregistered clients (single pool, hijack DNS, separate gateway)
  VLAN  99 – management / infrastructure (static range .100-.254, public DNS)
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


def infra_ghost_reservations(network_word: str, vlan: int, switch_hosts_raw: str) -> list:
    """Build ghost host reservations for infrastructure IPs in this VLAN's /24 block.

    These prevent Kea's allocator from ever handing out:
      .1  – default gateway
      .2  – SW1
      .3  – SW2
      .4  – Pi / portal
      .N  – any additional switch from SWITCH_HOSTS whose third octet == vlan

    Ghost MACs use the locally-administered prefix 02:00 so they can never
    match a real NIC: 02:00:c0:a8:<vlan_byte>:<host_byte>
    """
    host_octets = {1, 2, 3, 4}
    for host_str in switch_hosts_raw.split():
        host_str = host_str.strip()
        if not host_str:
            continue
        try:
            addr = ipaddress.IPv4Address(host_str)
            parts = str(addr).split(".")
            if int(parts[2]) == vlan:
                host_octets.add(int(parts[3]))
        except ValueError:
            continue

    reservations = []
    for octet in sorted(host_octets):
        ghost_mac = f"02:00:c0:a8:{vlan & 0xff:02x}:{octet:02x}"
        reservations.append({
            "hw-address": ghost_mac,
            "ip-address": f"{network_word}.{vlan}.{octet}",
            "user-context": {"infra-ghost": True},
        })
    return reservations


def make_vlan_subnet(network_word: str, vlan: int, prefix: int, switch_hosts_raw: str) -> dict:
    network = ipaddress.IPv4Network(f"{network_word}.{vlan}.0/{prefix}", strict=False)
    bounds = pool_bounds(prefix)
    return {
        "subnet": str(network),
        "id": vlan,
        "pools": [
            {
                "pool": (
                    f"{ip_at_offset(network, bounds['registered_start'])}"
                    f" - "
                    f"{ip_at_offset(network, bounds['registered_end'])}"
                )
            },
            {
                "pool": (
                    f"{ip_at_offset(network, bounds['blocked_start'])}"
                    f" - "
                    f"{ip_at_offset(network, bounds['blocked_end'])}"
                ),
                "client-classes": ["BLOCKED"],
            },
        ],
        "interface": f"eth0.{vlan}",
        "option-data": [
            {"name": "routers", "data": f"{network_word}.{vlan}.2"}
        ],
        "reservations": infra_ghost_reservations(network_word, vlan, switch_hosts_raw),
    }


def main():
    network_word   = require_env("NETWORK_WORD")

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

    portal_ip        = require_env("PORTAL_IP")
    hijack_dns_ip    = require_env("HIJACK_DNS_IP")
    switch_host      = require_env("SWITCH_HOST")
    unregistered_gw  = require_env("UNREGISTERED_GW")
    switch_hosts_raw = os.environ.get("SWITCH_HOSTS", switch_host)

    # VLANs 250 (unregistered) and 99 (management) are handled by the explicit
    # blocks below with their own pool/DNS/gateway config — skip them here.
    SPECIAL_VLANS = {99, 250}
    subnet4 = [
        make_vlan_subnet(network_word, vlan, prefix, switch_hosts_raw)
        for vlan, prefix in sorted(vlan_prefix_map.items())
        if vlan not in SPECIAL_VLANS
    ]

    # Unregistered clients — single pool, no blocked split, hijack DNS
    subnet4.append({
        "subnet": f"{network_word}.250.0/24",
        "id": 250,
        "pools": [
            {"pool": f"{network_word}.250.1 - {network_word}.250.255"}
        ],
        "interface": "eth0.250",
        "option-data": [
            {"name": "routers",             "data": unregistered_gw},
            {"name": "domain-name-servers", "data": hijack_dns_ip},
        ],
        "reservations": [],
    })

    # Management VLAN — lower range reserved for static infra, public DNS
    subnet4.append({
        "subnet": f"{network_word}.99.0/24",
        "id": 99,
        "pools": [
            {"pool": f"{network_word}.99.100 - {network_word}.99.254"}
        ],
        "interface": "eth0.99",
        "option-data": [
            {"name": "routers",             "data": switch_host},
            {"name": "domain-name-servers", "data": "8.8.8.8, 8.8.4.4"},
        ],
        "reservations": [],
    })

    interfaces = (
        [f"eth0.{v}" for v in sorted(vlan_prefix_map) if v not in SPECIAL_VLANS]
        + ["eth0.250", "eth0.99"]
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
            "renew-timer": 150,
            "rebind-timer": 240,
            "valid-lifetime": 300,
            "option-data": [
                {"name": "domain-name",         "data": "blackfriars.local"},
                {"name": "domain-name-servers",  "data": portal_ip},
            ],
            "client-classes": [
                {"name": "BLOCKED", "test": "0 == 1"}
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
