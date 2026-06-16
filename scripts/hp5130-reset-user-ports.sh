#!/bin/sh
set -e

# hp5130-reset-user-ports.sh
#
# Resets and configures user device interfaces based on USER_DEVICE_INTERFACES environment variable.
# This clears MAC-VLAN relations by doing shutdown/undo shutdown and applies consistent config.
#
# Environment variables required:
#   SWITCH_HOSTS - space-separated IP addresses of HP5130 switches (first one is used)
#   SWITCH_USER - SSH username
#   USER_DEVICE_INTERFACES - Comma-separated list of interface numbers (e.g., "12,13,14,15,16")
#
# The wired-unregistered VLAN ID is read from the WIRED_VLAN env var (default 250).
# The management VLAN ID is read from MANAGEMENT_VLAN (default 99).
# The list of possible user VLANs is read from VALID_VLANS (default 10,20,...,90).

WIRED_VLAN="${WIRED_VLAN:-250}"
MANAGEMENT_VLAN="${MANAGEMENT_VLAN:-99}"
VALID_VLANS="${VALID_VLANS:-10,20,30,40,50,60,70,80,90}"
VLANS_LIST=$(echo "$VALID_VLANS" | tr ',' ' ')

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Key path detection (match hp5130-acl.sh)
DEFAULT_KEY_PATH="/keys/id_rsa"
if [ -f "/home/admin/.ssh/id_rsa" ]; then
  DEFAULT_KEY_PATH="/home/admin/.ssh/id_rsa"
elif [ -f "$BASE_DIR/keys/hp5130_id_rsa" ]; then
  DEFAULT_KEY_PATH="$BASE_DIR/keys/hp5130_id_rsa"
fi

SWITCH_HOST="$(printf '%s' "${SWITCH_HOSTS:-}" | awk '{print $1}')"
[ -n "$SWITCH_HOST" ] || { echo "SWITCH_HOSTS required" >&2; exit 1; }
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-$DEFAULT_KEY_PATH}"

# Configure logging (match hp5130-acl.sh)
QUEUE_BASE="${ACL_QUEUE_DIR:-}"
if [ -z "$QUEUE_BASE" ]; then
  if [ -d "/acl-queue" ]; then
    QUEUE_BASE="/acl-queue"
  else
    QUEUE_BASE="$BASE_DIR/shared/acl-queue"
  fi
fi

LOG_FILE="${RESET_PORTS_LOG:-$QUEUE_BASE/hp5130-reset-ports.log}"
QUEUE_UMASK="${ACL_QUEUE_UMASK:-0002}"
QUEUE_GID="${ACL_QUEUE_GID:-}"

umask "$QUEUE_UMASK" 2>/dev/null || true
mkdir -p "$QUEUE_BASE" 2>/dev/null || true
if [ -n "$QUEUE_GID" ]; then
  chgrp "$QUEUE_GID" "$QUEUE_BASE" 2>/dev/null || true
fi
chmod 2775 "$QUEUE_BASE" 2>/dev/null || true

timestamp() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}

log() {
  printf '%s %s\n' "$(timestamp)" "$*" >> "$LOG_FILE" 2>/dev/null || true
}

# Required variables
: "${USER_DEVICE_INTERFACES:?USER_DEVICE_INTERFACES not set}"

log "START action=reset_ports switch=$SWITCH_HOST user=$SWITCH_USER interfaces=$USER_DEVICE_INTERFACES wired_vlan=$WIRED_VLAN mgmt_vlan=$MANAGEMENT_VLAN vlans_list=$VLANS_LIST"

# SSH configuration (match hp5130-acl.sh)
SSH_TTY_FLAG="${SSH_TTY_FLAG:--tt}"
SSH_HOSTKEY_OPTS="${SSH_HOSTKEY_OPTS:--o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa}"
SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT $SSH_HOSTKEY_OPTS -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3"

# Parse comma-separated interfaces using POSIX-compliant approach
INTERFACES_COUNT=0
for IFACE_NUM in $(echo "$USER_DEVICE_INTERFACES" | tr ',' ' '); do
    INTERFACES_COUNT=$((INTERFACES_COUNT + 1))
done

if [ "$INTERFACES_COUNT" -eq 0 ]; then
    log "ERROR reason=no_interfaces_specified"
    exit 1
fi

# Build SSH commands
COMMANDS="system-view"

for IFACE_NUM in $(echo "$USER_DEVICE_INTERFACES" | tr ',' ' '); do
    # Trim whitespace
    IFACE_NUM=$(echo "$IFACE_NUM" | xargs)

    log "CONFIG interface=GigabitEthernet1/0/${IFACE_NUM}"

    # Build commands for this interface
    COMMANDS="$COMMANDS
interface GigabitEthernet1/0/${IFACE_NUM}
shutdown
undo description
undo ip verify source
undo port-security port-mode
undo port-security intrusion-mode
undo port-security max-mac-count
undo port access vlan
undo port link-type
undo port trunk permit vlan all
undo mac-vlan enable
undo mac-authentication
undo web-auth enable
undo web-auth domain
undo dhcp snooping trust
undo arp detection trust
undo dhcp snooping check mac-address
undo mac-authentication max-user
undo mac-authentication domain
undo mac-authentication host-mode
undo dhcp snooping binding record
undo mac-authentication guest-vlan
undo port-security enable
interface GigabitEthernet1/0/${IFACE_NUM}
description wired port
port link-type access
port link-type hybrid
undo port hybrid vlan 1
port hybrid vlan ${VLANS_LIST} ${MANAGEMENT_VLAN} untagged
port hybrid vlan ${WIRED_VLAN} untagged
port hybrid pvid vlan ${WIRED_VLAN}
mac-vlan enable
mac-authentication
ip verify source ip-address mac-address
mac-authentication max-user 16
mac-authentication domain macauth
mac-authentication guest-vlan ${WIRED_VLAN}
mac-authentication host-mode multi-vlan
dhcp snooping binding record
dhcp snooping check mac-address
undo shutdown
quit"
done

# Return to system view and save
COMMANDS="$COMMANDS
save safely force
quit
quit"

# Execute via SSH (match hp5130-acl.sh approach)
log "SSH_EXEC key=$SWITCH_KEY_PATH host=$SWITCH_HOST"

temp_out=$(mktemp /tmp/ssh_out.XXXXXX)
temp_err=$(mktemp /tmp/ssh_err.XXXXXX)

ssh_start=$(date +%s)
set +e
printf "%s\n" "$COMMANDS" | ssh $SSH_TTY_FLAG $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$temp_out" 2> "$temp_err"
status=$?
set -e
ssh_end=$(date +%s)
ssh_duration=$((ssh_end - ssh_start))

if [ $status -ne 0 ]; then
    log "ERROR status=$status duration_sec=$ssh_duration stdout=$(cat "$temp_out" | tr '\n' ' ') stderr=$(cat "$temp_err" | tr '\n' ' ')"
    rm -f "$temp_out" "$temp_err"
    exit $status
else
    log "SUCCESS interfaces_configured=$INTERFACES_COUNT duration_sec=$ssh_duration"
    rm -f "$temp_out" "$temp_err"
fi

log "COMPLETE action=reset_ports interfaces=$INTERFACES_COUNT"
