#!/usr/bin/env python3
import argparse
import ipaddress
import os
import re
import subprocess
import sys


def _normalise_interface(ifname: str) -> str:
    """Convert a verbose interface name to the short form used by HP switches.

    Examples:
        Gigabitethernet1/0/17 -> GE1/0/17
        gigabitethernet1/0/17 -> GE1/0/17
        Ge1/0/17             -> Ge1/0/17 (unchanged)
        GE1/0/17             -> GE1/0/17 (unchanged)
    """
    prefix = "gigabitethernet"
    if ifname.lower().startswith(prefix):
        suffix = ifname[len(prefix):]
        return "GE" + suffix
    return ifname


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Retrieve IP addresses visible on a given switch interface"
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SWITCH_HOST", "192.168.99.2"),
        help="Switch IP/hostname (default: $SWITCH_HOST or 192.168.99.2)",
    )
    parser.add_argument(
        "--interface", required=True, help="Interface name (e.g. Ge1/0/17)"
    )
    parser.add_argument(
        "--subnet",
        default=None,
        help="Optional subnet (e.g. 192.168.1.0/24) to filter results",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("SWITCH_USER", "robert"),
        help="SSH username (default: $SWITCH_USER or 'robert')",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument(
        "--identity",
        default=os.path.expanduser("~/.ssh/id_rsa"),
        help="Path to SSH private key",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print the raw ARP output to stderr for troubleshooting",
    )

    args = parser.parse_args()
    user = args.user
    host = args.host
    port = args.port
    identity = os.path.expanduser(args.identity)
    interface = args.interface

    # Build the SSH command exactly as the working example
    ssh_cmd = [
        "ssh",
        "-tt",
        "-i", identity,
        "-p", str(port),
        "-o", "HostKeyAlgorithms=+ssh-rsa",
        "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=3",
        f"{user}@{host}",
        "screen-length disable\ndisplay arp",
    ]

    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        print("SSH command timed out", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        print(f"SSH failed (exit code {result.returncode})", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    output = result.stdout

    if args.debug:
        print("=== Raw ARP output ===", file=sys.stderr)
        print(output, file=sys.stderr)
        print("=== End raw ===", file=sys.stderr)

    ips: list[str] = []

    # Normalise the interface name so we also try the short form
    search_strings = [interface, _normalise_interface(interface)]

    for line in output.splitlines():
        if any(s.lower() in line.lower() for s in search_strings):
            ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            if ip_matches:
                ips.append(ip_matches[0])

    # Optionally restrict to a given subnet
    if args.subnet:
        network = ipaddress.ip_network(args.subnet, strict=False)
        ips = [ip for ip in ips if ipaddress.ip_address(ip) in network]

    if not ips:
        print("No IP addresses matched. Use --debug to inspect the ARP table.",
              file=sys.stderr)

    # Print the IPs, one per line
    for ip in ips:
        print(ip)


if __name__ == "__main__":
    main()
