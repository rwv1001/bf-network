#!/bin/sh
set -e

# hp5130-port-macs.sh
#
# Finds IP addresses (in a given subnet) of devices connected to a specific
# HP5130 switch port.  First queries the MAC address table for the port, then
# dumps the full ARP table (with paging disabled) and matches MACs locally.
#
# Usage:
#   hp5130-port-macs.sh <switch_host> <port> [subnet]
#
#   switch_host   – IP of the switch
#   port          – interface name, e.g. GigabitEthernet1/0/17
#   subnet        – CIDR subnet to filter (default 192.168.1.0/24)
#
# Environment (optional):
#   SWITCH_USER      – SSH user (default robert)
#   SWITCH_KEY_PATH  – path to SSH private key (auto-detected)
#   SWITCH_SSH_PORT  – SSH port (default 22)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Key path detection (mirrors hp5130-acl.sh) ---
DEFAULT_KEY_PATH="/keys/id_rsa"
if [ -f "/home/admin/.ssh/id_rsa" ]; then
  DEFAULT_KEY_PATH="/home/admin/.ssh/id_rsa"
elif [ -f "$BASE_DIR/keys/hp5130_id_rsa" ]; then
  DEFAULT_KEY_PATH="$BASE_DIR/keys/hp5130_id_rsa"
fi

SWITCH_HOST="${1:?Usage: $0 <switch_host> <port> [subnet]}"
PORT="${2:?Missing port argument}"
SUBNET="${3:-192.168.1.0/24}"
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-$DEFAULT_KEY_PATH}"

# --- SSH options ---
SSH_TTY_FLAG="${SSH_TTY_FLAG:--tt}"
SSH_HOSTKEY_OPTS="${SSH_HOSTKEY_OPTS:--o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa}"
SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT $SSH_HOSTKEY_OPTS -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3"

# --- Subnet helper ---
subnet_network=$(echo "$SUBNET" | cut -d/ -f1)
subnet_prefix=$(echo "$SUBNET" | cut -d/ -f2)

# --- Phase 1: Get MAC addresses on the port ---
MAC_LIST_CMD="display mac-address interface $PORT"

temp_out=$(mktemp /tmp/ssh_portmacs.XXXXXX)
temp_err=$(mktemp /tmp/ssh_portmacs_err.XXXXXX)

set +e
printf '%s\n' "$MAC_LIST_CMD" | \
  ssh $SSH_TTY_FLAG $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$temp_out" 2> "$temp_err"
status=$?
set -e

if [ $status -ne 0 ]; then
  echo "ERROR: SSH to $SWITCH_HOST failed (exit $status)" >&2
  cat "$temp_err" >&2
  rm -f "$temp_out" "$temp_err"
  exit $status
fi

# Parse MAC addresses from output
MACS=$(grep -oE '[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}' "$temp_out" || true)
rm -f "$temp_out" "$temp_err"

if [ -z "$MACS" ]; then
  echo "No MAC addresses found on $PORT" >&2
  exit 0
fi

# --- Phase 2: Dump the full ARP table (disable paging first) ---
ARP_CMD="screen-length disable
display arp"

temp_out=$(mktemp /tmp/ssh_portmacs2.XXXXXX)
temp_err=$(mktemp /tmp/ssh_portmacs2_err.XXXXXX)

set +e
printf '%s\n' "$ARP_CMD" | \
  ssh $SSH_TTY_FLAG $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$temp_out" 2> "$temp_err"
status=$?
set -e

if [ $status -ne 0 ]; then
  echo "ERROR: ARP table dump on $SWITCH_HOST failed (exit $status)" >&2
  cat "$temp_err" >&2
  rm -f "$temp_out" "$temp_err"
  exit $status
fi

ARP_OUTPUT=$(cat "$temp_out")
rm -f "$temp_out" "$temp_err"

# --- Phase 3: For each MAC, find its IP in the ARP table, filter by subnet ---
FOUND=""
for MAC in $MACS; do
  # Search ARP output for this MAC (case-insensitive, first match)
  arp_line=$(echo "$ARP_OUTPUT" | grep -i "$MAC" | head -1)
  if [ -z "$arp_line" ]; then
    continue
  fi

  # Extract IP (first field that looks like an IP)
  ip=$(echo "$arp_line" | grep -oE '^[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tr -d '[:space:]')
  if [ -z "$ip" ]; then
    continue
  fi

  # Check if IP is in the target subnet
  match=1
  if [ "$subnet_prefix" -ge 8 ]; then
    subnet_oct1=$(echo "$subnet_network" | cut -d. -f1)
    ip_oct1=$(echo "$ip" | cut -d. -f1)
    [ "$subnet_oct1" = "$ip_oct1" ] || match=0
  fi
  if [ "$subnet_prefix" -ge 16 ] && [ "$match" -eq 1 ]; then
    subnet_oct2=$(echo "$subnet_network" | cut -d. -f2)
    ip_oct2=$(echo "$ip" | cut -d. -f2)
    [ "$subnet_oct2" = "$ip_oct2" ] || match=0
  fi
  if [ "$subnet_prefix" -ge 24 ] && [ "$match" -eq 1 ]; then
    subnet_oct3=$(echo "$subnet_network" | cut -d. -f3)
    ip_oct3=$(echo "$ip" | cut -d. -f3)
    [ "$subnet_oct3" = "$ip_oct3" ] || match=0
  fi
  if [ "$subnet_prefix" -ge 32 ] && [ "$match" -eq 1 ]; then
    subnet_oct4=$(echo "$subnet_network" | cut -d. -f4)
    ip_oct4=$(echo "$ip" | cut -d. -f4)
    [ "$subnet_oct4" = "$ip_oct4" ] || match=0
  fi

  if [ "$match" -eq 1 ]; then
    echo "$ip"
    FOUND="$FOUND $ip"
  fi
done

if [ -z "$FOUND" ]; then
  echo "No IPs in $SUBNET found on $PORT" >&2
  exit 0
fi