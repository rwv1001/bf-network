#!/usr/bin/env python3
"""
Pair-aware mDNS reflector.

Reads /mdns/peers.json (or MDNS_PEERS_FILE) and forwards UDP/5353
multicast only along configured VLAN visibility edges.

A packet received on interface A is sent only to peer interfaces listed
for A. Packets sourced from one of our own interface IPs are dropped so
we do not bounce our own forwards (which would make visibility transitive).
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

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
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


def open_mdns_socket(ifname: str, ifaddr: str) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8") + b"\0")
    sock.bind(("", MDNS_PORT))

    mreq = socket.inet_aton(MDNS_GROUP) + socket.inet_aton(ifaddr)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ifaddr))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    sock.setblocking(False)
    return sock


class Reflector:
    def __init__(self, peers_file: str):
        self.peers_file = peers_file
        self.mtime = 0.0
        self.config: dict = {}
        self.socks: Dict[str, socket.socket] = {}
        self.addrs: Dict[str, str] = {}
        self.own_ips = set()
        self.peers: Dict[str, List[str]] = {}

    def close_all(self) -> None:
        for sock in self.socks.values():
            try:
                sock.close()
            except OSError:
                pass
        self.socks.clear()
        self.addrs.clear()
        self.own_ips.clear()
        self.peers.clear()

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
            try:
                sock = open_mdns_socket(ifname, ifaddr)
            except OSError as exc:
                log.error("cannot bind %s (%s): %s", ifname, ifaddr, exc)
                continue
            self.socks[ifname] = sock
            self.addrs[ifname] = ifaddr
            self.own_ips.add(ifaddr)
            self.peers[ifname] = peer_names
            log.info("listening on %s (%s) -> %s", ifname, ifaddr, ",".join(peer_names))
        if len(self.socks) < 2:
            log.warning("need at least two live interfaces; reflector idle")

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

    def forward(self, src_if: str, data: bytes, src_ip: str) -> None:
        if src_ip in self.own_ips:
            return
        for dst_if in self.peers.get(src_if, []):
            sock = self.socks.get(dst_if)
            if sock is None:
                continue
            try:
                sock.sendto(data, (MDNS_GROUP, MDNS_PORT))
            except OSError as exc:
                log.debug("send %s -> %s failed: %s", src_if, dst_if, exc)

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
            items: List[Tuple[str, socket.socket]] = list(self.socks.items())
            readable, _, _ = select.select([s for _, s in items], [], [], RELOAD_SEC)
            if not readable:
                continue
            sock_to_if = {s: name for name, s in items}
            for sock in readable:
                src_if = sock_to_if.get(sock)
                if not src_if:
                    continue
                try:
                    data, addr = sock.recvfrom(65535)
                except OSError:
                    continue
                if not data or not addr:
                    continue
                self.forward(src_if, data, addr[0])


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
