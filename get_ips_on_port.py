#!/usr/bin/env python3
import argparse
import ipaddress
import os
import re
import subprocess
import sys


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
    ips: list[str] = []

    # Parse each line for the desired interface
    for line in output.splitlines():
        if interface.lower() in line.lower():
            # Extract the first IPv4 address on the line
            ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            if ip_matches:
                ips.append(ip_matches[0])

    # Optionally restrict to a given subnet
    if args.subnet:
        network = ipaddress.ip_network(args.subnet, strict=False)
        ips = [ip for ip in ips if ipaddress.ip_address(ip) in network]

    # Print the IPs, one per line
    for ip in ips:
        print(ip)


if __name__ == "__main__":
    main()
