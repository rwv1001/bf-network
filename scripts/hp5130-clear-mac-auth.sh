#!/bin/sh
set -e

# Clear all MAC authentication sessions on the HP5130 switch
# NOTE: mac-authentication mac-clear may not work reliably on HP5130.
# The reset-user-ports.sh script handles this via shutdown/undo shutdown.

# Determine paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configure logging
QUEUE_BASE="${ACL_QUEUE_DIR:-}"
if [ -z "$QUEUE_BASE" ]; then
  if [ -d "/acl-queue" ]; then
    QUEUE_BASE="/acl-queue"
  else
    QUEUE_BASE="$BASE_DIR/shared/acl-queue"
  fi
fi

LOG_FILE="${CLEAR_MAC_AUTH_LOG:-$QUEUE_BASE/hp5130-clear-mac-auth.log}"
mkdir -p "$QUEUE_BASE" 2>/dev/null || true

timestamp() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}

log() {
  printf '%s %s\n' "$(timestamp)" "$*" | tee -a "$LOG_FILE" 2>/dev/null || true
}

# SSH configuration
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

SSH_OPTS="-tt -i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

log "START action=clear_mac_auth switch=$SWITCH_HOST user=$SWITCH_USER"

# Note: This command often fails on HP5130. Port reset (shutdown/undo shutdown) is more reliable.
set +e
OUTPUT=$(ssh $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" <<'EOF' 2>&1
screen-length disable
system-view
mac-authentication mac-clear
quit
save force
quit
EOF
)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 0 ]; then
    log "SUCCESS action=clear_mac_auth"
else
    log "WARN action=clear_mac_auth exit_code=$EXIT_CODE output=$(echo "$OUTPUT" | tr '\n' ' ') note=command_may_not_be_supported"
    # Don't fail - the port reset handles this
fi

log "COMPLETE action=clear_mac_auth"
exit 0
