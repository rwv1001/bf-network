#!/usr/bin/env python3
"""
Connect to an HP5130 switch, list MAC addresses on a given port,
then resolve each MAC to an IP via ARP table, and filter to addresses
belonging to a specified subnet.

Usage:
    export SWITCH_USER="admin"
    export SWITCH_PASSWORD="password"
    python get_ips_on_port.py \
        --host 192.168.1.1 \
        --interface GigabitEthernet1/0/17 \
        --subnet 192.168.1.0/24
"""

import argparse
import ipaddress
import os
import re
import sys
import time

try:
    import paramiko
except ImportError:
    print("paramiko is required. Install with: pip install paramiko", file=sys.stderr)
    sys.exit(1)


def get_ssh_client(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    """Return an open SSH client connected to the switch."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=username,
                   password=password, timeout=30, look_for_keys=False,
                   allow_agent=False)
    return client


def run_command(client: paramiko.SSHClient, command: str) -> str:
    """Run a command on the switch and return stdout as a string."""
    stdin, stdout, stderr = client.exec_command(command)
    # Wait for command to finish
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        err = stderr.read().decode().strip()
        raise RuntimeError(f"Command exited with status {exit_status}: {err}")
    return stdout.read().decode()


def parse_mac_addresses(output: str) -> list[str]:
    """
    Extract MAC addresses in hyphen format (e.g. 2ec5-987d-e8e0) from
    the output of 'display mac-address interface ...'.
    """
    macs = []
    # Pattern: hyphen-separated hex groups of 1-4 chars each, exactly 6 groups
    # e.g. 2ec5-987d-e8e0
    mac_re = re.compile(
        r'(?<!\w)'
        r'(?:[0-9a-fA-F]{1,4}-){5}[0-9a-fA-F]{1,4}'
        r'(?!\w)'
    )
    for line in output.splitlines():
        # Skip empty lines and headers
        if not line.strip():
            continue
        m = mac_re.search(line)
        if m:
            macs.append(m.group(0).lower())
    return macs


def get_ip_for_mac(client: paramiko.SSHClient, mac: str) -> str | None:
    """
    Run 'display arp | include <mac>' and return the first IP address found,
    or None.
    """
    command = f"display arp | include {mac}"
    try:
        output = run_command(client, command)
    except RuntimeError:
        return None
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # First token should be an IP address (dotted decimal)
        ip_candidate = line.split()[0] if line.split() else ""
        try:
            ipaddress.IPv4Address(ip_candidate)
            return ip_candidate
        except (ValueError, IndexError):
            continue
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Find IPs on a switch port within a given subnet.")
    parser.add_argument("--host", required=True, help="Switch management IP or hostname")
    parser.add_argument("--interface", required=True,
                        help="Port name, e.g. GigabitEthernet1/0/17")
    parser.add_argument("--subnet", default="192.168.1.0/24",
                        help="Subnet to filter (default: 192.168.1.0/24)")
    parser.add_argument("--username", default=os.environ.get("SWITCH_USER"),
                        help="SSH username (env: SWITCH_USER)")
    parser.add_argument("--password", default=os.environ.get("SWITCH_PASSWORD"),
                        help="SSH password (env: SWITCH_PASSWORD)")
    parser.add_argument("--ssh-port", type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Seconds to wait between commands (default: 1.0)")
    args = parser.parse_args()

    if not args.username:
        print("Error: SSH username not provided. Set SWITCH_USER or pass --username.",
              file=sys.stderr)
        sys.exit(1)
    if not args.password:
        print("Error: SSH password not provided. Set SWITCH_PASSWORD or pass --password.",
              file=sys.stderr)
        sys.exit(1)

    try:
        subnet = ipaddress.IPv4Network(args.subnet, strict=True)
    except ValueError as e:
        print(f"Invalid subnet: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to {args.host} ...", file=sys.stderr)
    try:
        client = get_ssh_client(args.host, args.username, args.password, args.ssh_port)
    except Exception as e:
        print(f"SSH connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        # Disable paging so we get the full output
        run_command(client, "screen-length disable")
        time.sleep(args.delay)

        # Get MAC addresses on the port
        cmd_macs = f"display mac-address interface {args.interface}"
        print(f"Running: {cmd_macs}", file=sys.stderr)
        mac_output = run_command(client, cmd_macs)
        macs = parse_mac_addresses(mac_output)
        print(f"Found {len(macs)} MAC address(es) on {args.interface}", file=sys.stderr)

        results: list[str] = []
        for mac in macs:
            time.sleep(args.delay)
            ip = get_ip_for_mac(client, mac)
            if ip is None:
                print(f"MAC {mac}: no ARP entry", file=sys.stderr)
                continue
            try:
                ip_obj = ipaddress.IPv4Address(ip)
            except ValueError:
                print(f"MAC {mac}: invalid IP {ip}", file=sys.stderr)
                continue
            if ip_obj in subnet:
                results.append(ip)
                print(f"MAC {mac} -> {ip} (in subnet)", file=sys.stderr)
            else:
                print(f"MAC {mac} -> {ip} (outside subnet)", file=sys.stderr)

        client.close()

        # Output results one per line on stdout
        for ip in results:
            print(ip)

        if not results:
            print("No matching IPs found.", file=sys.stderr)
            sys.exit(0)

    except Exception as e:
        print(f"Error during switch operations: {e}", file=sys.stderr)
        try:
            client.close()
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
