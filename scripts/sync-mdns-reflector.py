#!/usr/bin/env python3
"""
Build mdns/peers.json from VlanMapping.visible_vlans, ensure Pi VLAN
interfaces exist, and recreate the mdns container.

Safe to run from the web container (host network + docker.sock +
/etc/systemd/network mount) or directly on the host.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys

log = logging.getLogger("sync-mdns")


def _net_word() -> str:
    return os.getenv("NETWORK_WORD", "192.168")


def _wan_iface() -> str:
    return os.getenv("WAN_IFACE", "eth0")


def _portal_ip_byte() -> int:
    try:
        return int(os.getenv("PORTAL_IP_BYTE", "4"))
    except (TypeError, ValueError):
        return 4


def _compose_dir() -> str:
    return os.getenv("GIT_REPO_DIR") or os.getenv("BF_NETWORK_DIR") or "/home/admin/bf-network"


def _peers_path() -> str:
    return os.getenv("MDNS_PEERS_PATH", os.path.join(_compose_dir(), "mdns", "peers.json"))


def _network_dir() -> str:
    return os.getenv("PI_NETWORK_DIR", "/etc/systemd/network")





def _ifname(vlan_id: int) -> str:
    return f"{_wan_iface()}.{int(vlan_id)}"

def _isp_subnets():
    """{vlan_id: (addr_on_pi, prefixlen)} from ISPRouter."""
    out = {}
    try:
        from models import ISPRouter
        for r in ISPRouter.query.all():
            if not r.vlan_id or not r.subnet:
                continue
            net = __import__("ipaddress").ip_network(str(r.subnet), strict=False)
            # Use PORTAL_IP_BYTE inside the ISP subnet when it falls inside the net
            candidate = net.network_address + _portal_ip_byte()
            if candidate in net and candidate not in (net.network_address, net.broadcast_address):
                addr = str(candidate)
            else:
                addr = str(net.network_address + 4)
            out[int(r.vlan_id)] = (addr, net.prefixlen)
    except Exception:
        pass
    return out


def _vlan_addr(vlan_id: int) -> str:
    isp = _isp_subnets().get(int(vlan_id))
    if isp:
        return isp[0]
    return f"{_net_word()}.{int(vlan_id)}.{_portal_ip_byte()}"


def _isp_pi_ips():
    """Parse ISP_PI_IPS='1:192.168.1.4,2:192.168.3.4' and ISP_PI_PREFIXES='1:24,2:24'."""
    addrs, pfxs = {}, {}
    for part in (os.getenv("ISP_PI_IPS") or "").split(","):
        part = part.strip()
        if ":" not in part:
            continue
        vid, ip = part.split(":", 1)
        if vid.strip().isdigit() and ip.strip():
            addrs[int(vid)] = ip.strip()
    for part in (os.getenv("ISP_PI_PREFIXES") or "").split(","):
        part = part.strip()
        if ":" not in part:
            continue
        vid, pfx = part.split(":", 1)
        if vid.strip().isdigit() and pfx.strip().isdigit():
            pfxs[int(vid)] = int(pfx)
    return addrs, pfxs


def _vlan_prefix(vlan_id: int) -> int:
    _, pfxs = _isp_pi_ips()
    if int(vlan_id) in pfxs:
        return pfxs[int(vlan_id)]
    isp = _isp_subnets().get(int(vlan_id))
    if isp:
        return int(isp[1])
    return 24


def _vlan_addr(vlan_id: int) -> str:
    addrs, _ = _isp_pi_ips()
    if int(vlan_id) in addrs:
        return addrs[int(vlan_id)]
    isp = _isp_subnets().get(int(vlan_id))
    if isp:
        return isp[0]
    return f"{_net_word()}.{int(vlan_id)}.{_portal_ip_byte()}"

def visibility_graph(entries) -> dict:
    """Return {vlan_id: set(peer_vlan_ids)} from mapping rows."""
    graph = {}
    for entry in entries:
        vid = getattr(entry, "vlan_id", None)
        if not vid:
            continue
        raw = getattr(entry, "visible_vlans", None) or ""
        peers = set()
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit() and int(part) != int(vid):
                peers.add(int(part))
        graph[int(vid)] = peers

    # Treat visibility as undirected even if one side was saved stale.
    for vid, peers in list(graph.items()):
        for peer in list(peers):
            graph.setdefault(peer, set()).add(vid)
    return graph


def write_systemd_vlan(vlan_id: int) -> None:
    netdir = _network_dir()
    os.makedirs(netdir, exist_ok=True)
    wan = _wan_iface()
    name = _ifname(vlan_id)
    addr = _vlan_addr(vlan_id)
    netdev = os.path.join(netdir, f"10-{name}.netdev")
    network = os.path.join(netdir, f"10-{name}.network")

    netdev_body = (
        "[NetDev]\n"
        f"Name={name}\n"
        "Kind=vlan\n"
        "\n"
        "[VLAN]\n"
        f"Id={int(vlan_id)}\n"
    )
    # Parent NIC is configured elsewhere; only create the VLAN netdev + address.
    network_body = (
        "[Match]\n"
        f"Name={name}\n"
        "\n"
        "[Network]\n"
        f"Address={addr}/{_vlan_prefix(vlan_id)}\n"
        "ConfigureWithoutCarrier=yes\n"
        "LinkLocalAddressing=ipv6\n"
    )
    for path, body in ((netdev, netdev_body), (network, network_body)):
        existing = ""
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                existing = handle.read()
        if existing != body:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(body)
            log.info("wrote %s", path)

    parent_hint = os.path.join(netdir, f"10-{wan}.network")
    if os.path.exists(parent_hint):
        return
    # If the parent .network is missing VLAN= lines, systemd-networkd may
    # still attach .netdev files keyed by Name. Leave parent files alone.


def apply_interfaces(vlan_ids) -> None:
    wan = _wan_iface()
    for vlan_id in vlan_ids:
        name = _ifname(vlan_id)
        addr = _vlan_addr(vlan_id)
        write_systemd_vlan(vlan_id)
        subprocess.run(
            ["ip", "link", "add", "link", wan, "name", name, "type", "vlan", "id", str(vlan_id)],
            capture_output=True,
            text=True,
        )
        subprocess.run(["ip", "link", "set", name, "up"], capture_output=True, text=True)
        subprocess.run(
            ["ip", "addr", "replace", f"{addr}/{_vlan_prefix(vlan_id)}", "dev", name],
            capture_output=True,
            text=True,
        )


def build_peers_json(graph: dict) -> dict:
    out = {}
    for vid, peers in sorted(graph.items()):
        if not peers:
            continue
        out[_ifname(vid)] = {
            "vlan_id": vid,
            "addr": _vlan_addr(vid),
            "peers": [_ifname(p) for p in sorted(peers)],
        }
    return out


def write_peers(data: dict) -> str:
    path = _peers_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = json.dumps(data, indent=2) + "\n"
    old = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            old = handle.read()
    if old != payload:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload)
        log.info("wrote %s", path)
    return path


def compose_mdns(action: str) -> None:
    compose = os.path.join(_compose_dir(), "docker-compose.yml")
    cmd = ["docker", "compose", "-f", compose, action, "mdns"]
    if action == "up":
        cmd = ["docker", "compose", "-f", compose, "up", "-d", "mdns"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            log.warning("docker compose %s mdns failed: %s", action, result.stderr.strip())
        else:
            log.info("docker compose %s mdns: %s", action, (result.stdout or "ok").strip())
    except Exception as exc:
        log.warning("docker compose %s mdns error: %s", action, exc)


def sync_from_graph(graph: dict) -> dict:
    active = {vid: peers for vid, peers in graph.items() if peers}
    needed = set(active) | {p for peers in active.values() for p in peers}
    if needed:
        apply_interfaces(sorted(needed))
    peers = build_peers_json(active)
    write_peers(peers)
    if len(peers) >= 2:
        compose_mdns("up")
    else:
        compose_mdns("stop")
        log.info("no visible-VLAN pairs; mdns reflector stopped")
    return peers


def sync_from_db() -> dict:
    from core.vlan_utils import get_vlan_entries

    return sync_from_graph(visibility_graph(get_vlan_entries()))


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s sync-mdns %(levelname)s %(message)s",
    )
    try:
        peers = sync_from_db()
    except Exception:
        log.exception("sync failed")
        return 1
    print(json.dumps(peers, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
