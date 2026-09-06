#!/usr/bin/env python3
"""
Pair-aware multicast discovery reflector.

Reads /mdns/peers.json (or MDNS_PEERS_FILE) and forwards printer/device
discovery multicast only along configured VLAN visibility edges.

A packet received on interface A is sent only to peer interfaces listed
for A. Packets sourced from one of our own interface IPs are dropped so
we do not bounce our own forwards (which would make visibility transitive).

Subnet-broadcast discovery (SNMP, SLP) is relayed along the same edges,
re-emitted with the original client's source address so the printer replies
directly to the client over normal routing.

Forwarding is dual-stack and family-crossing: a query heard on IPv6 is
re-emitted on peers over both IPv6 and IPv4 (and vice versa), because e.g.
Windows may probe only over IPv6 while printers speak only IPv4. mDNS/WSD
payloads carry IPv4 records/URLs, so they stay valid across families.
"""

from __future__ import annotations

import json
import logging
import os
import select
import socket
import struct
import sys
import time
from typing import Dict, List, Tuple

PROTOCOLS = [
    {"name": "mdns", "group": "224.0.0.251", "group6": "ff02::fb", "port": 5353, "ttl": 255},
    {"name": "wsd", "group": "239.255.255.250", "group6": "ff02::c", "port": 3702, "ttl": 1},
    {"name": "ssdp", "group": "239.255.255.250", "group6": "ff02::c", "port": 1900, "ttl": 4},
]
BCAST_PORTS = [
    int(p)
    for p in os.getenv("DISCOVERY_BCAST_PORTS", "161,427,3289,10004,22222").split(",")
    if p.strip()
]
PEERS_FILE = os.getenv("MDNS_PEERS_FILE", "/mdns/peers.json")
RELOAD_SEC = float(os.getenv("MDNS_RELOAD_SEC", "5"))
LOG_LEVEL = os.getenv("MDNS_LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s mdns-reflector %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("mdns-reflector")


def load_peers(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("peers.json must be an object keyed by interface name")
    return data


def iface_ipv4(ifname: str) -> str | None:
    import fcntl

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(
            fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack("256s", ifname.encode("utf-8")[:15]),
            )[20:24]
        )
    except OSError:
        return None
    finally:
        sock.close()


def iface_broadcast(ifname: str) -> str | None:
    import fcntl

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(
            fcntl.ioctl(
                sock.fileno(),
                0x8919,  # SIOCGIFBRDADDR
                struct.pack("256s", ifname.encode("utf-8")[:15]),
            )[20:24]
        )
    except OSError:
        return None
    finally:
        sock.close()


def iface_ipv6_addrs(ifname: str) -> List[str]:
    addrs = []
    try:
        with open("/proc/net/if_inet6", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == ifname:
                    raw = parts[0]
                    packed = bytes.fromhex(raw)
                    addrs.append(socket.inet_ntop(socket.AF_INET6, packed).lower())
    except OSError:
        pass
    return addrs


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_udp_packet(src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
    )
    header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    csum = _checksum(pseudo + header) or 0xFFFF
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, csum) + payload

    def ip_hdr(check: int) -> bytes:
        return struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 0, 0, 64,
            socket.IPPROTO_UDP, check,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        )

    return ip_hdr(_checksum(ip_hdr(0))) + udp


def open_bcast_socket(ifname: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8") + b"\0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
    sock.bind(("", port))
    sock.setblocking(False)
    return sock


def open_raw_socket(ifname: str) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8") + b"\0")
    return sock


def open_discovery_socket(ifname: str, ifaddr: str, protocol: dict) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8") + b"\0")
    sock.bind(("", int(protocol["port"])))

    mreq = socket.inet_aton(protocol["group"]) + socket.inet_aton(ifaddr)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ifaddr))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(protocol["ttl"]))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    sock.setblocking(False)
    return sock


def open_discovery_socket6(ifname: str, ifindex: int, protocol: dict) -> socket.socket:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8") + b"\0")
    sock.bind(("", int(protocol["port"])))

    mreq = socket.inet_pton(socket.AF_INET6, protocol["group6"]) + struct.pack("@I", ifindex)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, int(protocol["ttl"]))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
    sock.setblocking(False)
    return sock


class Reflector:
    def __init__(self, peers_file: str):
        self.peers_file = peers_file
        self.mtime = 0.0
        self.config: dict = {}
        self.socks: Dict[Tuple[str, str, str], socket.socket] = {}
        self.addrs: Dict[str, str] = {}
        self.ifindexes: Dict[str, int] = {}
        self.own_ips = set()
        self.peers: Dict[str, List[str]] = {}
        self.bcast_socks: Dict[Tuple[str, int], socket.socket] = {}
        self.raw_socks: Dict[str, socket.socket] = {}
        self.bcasts: Dict[str, str] = {}
        self.recent: Dict[tuple, float] = {}

    def close_all(self) -> None:
        for sock in (
            list(self.socks.values())
            + list(self.bcast_socks.values())
            + list(self.raw_socks.values())
        ):
            try:
                sock.close()
            except OSError:
                pass
        self.socks.clear()
        self.addrs.clear()
        self.ifindexes.clear()
        self.own_ips.clear()
        self.peers.clear()
        self.bcast_socks.clear()
        self.raw_socks.clear()
        self.bcasts.clear()
        self.recent.clear()

    def apply_config(self, config: dict) -> None:
        self.close_all()
        self.config = config
        for ifname, meta in config.items():
            ifaddr = (meta or {}).get("addr") or iface_ipv4(ifname)
            peer_names = list((meta or {}).get("peers") or [])
            if not ifaddr:
                log.warning("skip %s: no IPv4 address yet", ifname)
                continue
            if not peer_names:
                log.info("skip %s: no peers", ifname)
                continue
            self.addrs[ifname] = ifaddr
            self.own_ips.add(ifaddr)
            for addr6 in iface_ipv6_addrs(ifname):
                self.own_ips.add(addr6)
            try:
                ifindex = socket.if_nametoindex(ifname)
            except OSError:
                log.warning("skip %s: no interface index", ifname)
                continue
            self.ifindexes[ifname] = ifindex
            self.peers[ifname] = peer_names
            for protocol in PROTOCOLS:
                proto_name = protocol["name"]
                try:
                    sock = open_discovery_socket(ifname, ifaddr, protocol)
                except OSError as exc:
                    log.error(
                        "cannot bind %s/%s (%s %s:%s): %s",
                        ifname,
                        proto_name,
                        ifaddr,
                        protocol["group"],
                        protocol["port"],
                        exc,
                    )
                    continue
                self.socks[(ifname, proto_name, "4")] = sock
                try:
                    sock6 = open_discovery_socket6(ifname, ifindex, protocol)
                    self.socks[(ifname, proto_name, "6")] = sock6
                except OSError as exc:
                    log.error(
                        "cannot bind %s/%s v6 (%s:%s): %s",
                        ifname, proto_name, protocol["group6"], protocol["port"], exc,
                    )
                log.info(
                    "listening on %s/%s (%s %s:%s + %s) -> %s",
                    ifname,
                    proto_name,
                    ifaddr,
                    protocol["group"],
                    protocol["port"],
                    protocol["group6"],
                    ",".join(peer_names),
                )
            self._setup_broadcast(ifname, peer_names)
        live_ifaces = {ifname for ifname, _, _ in self.socks}
        if len(live_ifaces) < 2:
            log.warning("need at least two live interfaces; reflector idle")

    def _setup_broadcast(self, ifname: str, peer_names: List[str]) -> None:
        bcast = iface_broadcast(ifname)
        if not bcast or not BCAST_PORTS:
            return
        self.bcasts[ifname] = bcast
        try:
            self.raw_socks[ifname] = open_raw_socket(ifname)
        except OSError as exc:
            log.error("cannot open raw socket on %s: %s", ifname, exc)
            return
        for port in BCAST_PORTS:
            try:
                self.bcast_socks[(ifname, port)] = open_bcast_socket(ifname, port)
            except OSError as exc:
                log.error("cannot bind %s broadcast udp/%s: %s", ifname, port, exc)
        log.info(
            "relaying broadcast udp/%s on %s (bcast %s) -> %s",
            ",".join(str(p) for p in BCAST_PORTS), ifname, bcast, ",".join(peer_names),
        )

    def maybe_reload(self) -> None:
        try:
            mtime = os.path.getmtime(self.peers_file)
        except OSError:
            return
        if mtime == self.mtime:
            return
        try:
            config = load_peers(self.peers_file)
        except Exception as exc:
            log.error("failed to read %s: %s", self.peers_file, exc)
            return
        self.mtime = mtime
        log.info("loaded %s (%d interfaces)", self.peers_file, len(config))
        self.apply_config(config)

    def forward(self, src_if: str, protocol: dict, data: bytes, src_ip: str) -> None:
        if src_ip.split("%")[0].lower() in self.own_ips:
            return
        for dst_if in self.peers.get(src_if, []):
            sock4 = self.socks.get((dst_if, protocol["name"], "4"))
            if sock4 is not None:
                try:
                    sock4.sendto(data, (protocol["group"], int(protocol["port"])))
                except OSError as exc:
                    log.debug("send %s/%s -> %s v4 failed: %s", src_if, protocol["name"], dst_if, exc)
            sock6 = self.socks.get((dst_if, protocol["name"], "6"))
            ifindex = self.ifindexes.get(dst_if)
            if sock6 is not None and ifindex:
                try:
                    sock6.sendto(data, (protocol["group6"], int(protocol["port"]), 0, ifindex))
                except OSError as exc:
                    log.debug("send %s/%s -> %s v6 failed: %s", src_if, protocol["name"], dst_if, exc)

    def _is_duplicate(self, key: tuple) -> bool:
        now = time.time()
        if len(self.recent) > 2048:
            self.recent = {k: t for k, t in self.recent.items() if now - t < 3.0}
        seen = self.recent.get(key)
        if seen is not None and now - seen < 3.0:
            return True
        self.recent[key] = now
        return False

    def _handle_broadcast(self, sock: socket.socket, key: Tuple[str, int]) -> None:
        src_if, port = key
        try:
            data, ancdata, _, addr = sock.recvmsg(65535, socket.CMSG_SPACE(64))
        except OSError:
            return
        if not data or not addr:
            return
        dst_ip = None
        for level, ctype, cdata in ancdata:
            if level == socket.IPPROTO_IP and ctype == socket.IP_PKTINFO:
                dst_ip = socket.inet_ntoa(cdata[8:12])
        # Unicast replies route themselves; only true broadcasts need relaying.
        if dst_ip not in ("255.255.255.255", self.bcasts.get(src_if)):
            return
        self.forward_broadcast(src_if, port, data, addr[0], addr[1])

    def forward_broadcast(self, src_if: str, port: int, data: bytes, src_ip: str, src_port: int) -> None:
        if src_ip in self.own_ips:
            return
        if self._is_duplicate((src_ip, src_port, port, hash(data))):
            return
        for dst_if in self.peers.get(src_if, []):
            raw = self.raw_socks.get(dst_if)
            dst_bcast = self.bcasts.get(dst_if)
            if raw is None or not dst_bcast:
                continue
            try:
                raw.sendto(
                    build_udp_packet(src_ip, src_port, dst_bcast, port, data),
                    (dst_bcast, port),
                )
            except OSError as exc:
                log.debug("bcast relay %s -> %s udp/%s failed: %s", src_if, dst_if, port, exc)

    def run(self) -> None:
        log.info("starting, peers file %s", self.peers_file)
        last_reload = 0.0
        while True:
            now = time.time()
            if now - last_reload >= RELOAD_SEC:
                self.maybe_reload()
                last_reload = now
            if not self.socks:
                time.sleep(RELOAD_SEC)
                continue
            mcast_map = {s: key for key, s in self.socks.items()}
            bcast_map = {s: key for key, s in self.bcast_socks.items()}
            readable, _, _ = select.select(
                list(mcast_map) + list(bcast_map), [], [], RELOAD_SEC
            )
            if not readable:
                continue
            protocols = {p["name"]: p for p in PROTOCOLS}
            for sock in readable:
                if sock in bcast_map:
                    self._handle_broadcast(sock, bcast_map[sock])
                    continue
                key = mcast_map.get(sock)
                if not key:
                    continue
                src_if, proto_name, _fam = key
                protocol = protocols.get(proto_name)
                if not protocol:
                    continue
                try:
                    data, addr = sock.recvfrom(65535)
                except OSError:
                    continue
                if not data or not addr:
                    continue
                self.forward(src_if, protocol, data, addr[0])


def main() -> int:
    try:
        Reflector(PEERS_FILE).run()
    except KeyboardInterrupt:
        return 0
    except Exception:
        log.exception("fatal")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
