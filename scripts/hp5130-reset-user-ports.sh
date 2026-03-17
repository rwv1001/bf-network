#!/bin/sh
set -e

# hp5130-reset-user-ports.sh
#
# Resets and configures user device interfaces based on USER_DEVICE_INTERFACES environment variable.
# This clears MAC-VLAN relations by doing shutdown/undo shutdown and applies consistent config.
#
# Environment variables required:
#   SWITCH_HOST - IP address of the HP5130 switch
#   SWITCH_USER - SSH username
#   USER_DEVICE_INTERFACES - Comma-separated list of interface numbers (e.g., "12,13,14,15,16")
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Key path detection (match hp5130-acl.sh)
DEFAULT_KEY_PATH="/keys/id_rsa"
if [ -f "/home/admin/.ssh/id_rsa" ]; then
  DEFAULT_KEY_PATH="/home/admin/.ssh/id_rsa"
elif [ -f "$BASE_DIR/keys/hp5130_id_rsa" ]; then
  DEFAULT_KEY_PATH="$BASE_DIR/keys/hp5130_id_rsa"
fi

SWITCH_HOST="${SWITCH_HOST:?SWITCH_HOST required}"
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

log "START action=reset_ports switch=$SWITCH_HOST user=$SWITCH_USER interfaces=$USER_DEVICE_INTERFACES"

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
port link-type hybrid
undo port hybrid vlan 1
port hybrid vlan 10 20 30 40 50 60 70 80 90 99 untagged
port hybrid vlan 250 untagged
port hybrid pvid vlan 250
mac-vlan enable
ip verify source ip-address mac-address
mac-authentication max-user 16
mac-authentication domain macauth
mac-authentication guest-vlan 250
mac-authentication host-mode multi-vlan
port-security port-mode mac-authentication
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
