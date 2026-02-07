#!/bin/sh
set -eu

ACTION="${1:-}"
IP_ADDRESS="${2:-}"

if [ -z "$ACTION" ] || [ -z "$IP_ADDRESS" ]; then
  echo "Usage: $0 {block|unblock} <ip_address>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_KEY_PATH="/keys/id_rsa"
if [ -f "/home/admin/.ssh/id_rsa" ]; then
  DEFAULT_KEY_PATH="/home/admin/.ssh/id_rsa"
elif [ -f "$BASE_DIR/keys/hp5130_id_rsa" ]; then
  DEFAULT_KEY_PATH="$BASE_DIR/keys/hp5130_id_rsa"
fi

SWITCH_HOST="${SWITCH_HOST:-192.168.1.3}"
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-$DEFAULT_KEY_PATH}"
KEA_CONFIG_PATH="${KEA_CONFIG_PATH:-}"
PYTHON_BIN="${PYTHON_BIN:-}"

if [ -z "$KEA_CONFIG_PATH" ]; then
  if [ -f "/kea/config/dhcp4.json" ]; then
    KEA_CONFIG_PATH="/kea/config/dhcp4.json"
  else
    KEA_CONFIG_PATH="$BASE_DIR/kea/config/dhcp4.json"
  fi
fi

if [ -z "$PYTHON_BIN" ]; then
  PYTHON_BIN="$(command -v python3 2>/dev/null || true)"
fi

QUEUE_BASE="${ACL_QUEUE_DIR:-}"
if [ -z "$QUEUE_BASE" ]; then
  if [ -d "/acl-queue" ]; then
    QUEUE_BASE="/acl-queue"
  else
    QUEUE_BASE="$BASE_DIR/shared/acl-queue"
  fi
fi

LOG_FILE="${ACL_LOG_FILE:-$QUEUE_BASE/hp5130-acl.log}"
QUEUE_FILE="${ACL_QUEUE_FILE:-$QUEUE_BASE/hp5130-acl.queue}"
QUEUE_PID_FILE="${ACL_QUEUE_PID:-$QUEUE_BASE/hp5130-acl.pid}"
QUEUE_INTERVAL="${ACL_QUEUE_INTERVAL:-3}"
QUEUE_DISABLE="${ACL_QUEUE_DISABLE:-0}"  # Corrected: Use ACL_QUEUE_DISABLE (was QUEUE_DISABLE in your command, but script checks this)
QUEUE_WORKER="${ACL_QUEUE_WORKER:-$SCRIPT_DIR/hp5130-acl-queue.sh}"
DEDUP_WINDOW="${ACL_DEDUP_WINDOW:-3}"
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

is_valid_ip() {
  echo "$1" | awk -F. 'NF==4 && $1>=0 && $1<=255 && $2>=0 && $2<=255 && $3>=0 && $3<=255 && $4>=0 && $4<=255 {exit 0} {exit 1}'
}

if ! is_valid_ip "$IP_ADDRESS"; then
  log "SKIP_INVALID action=$ACTION ip=$IP_ADDRESS"
  exit 0
fi

SAFE_IP="$(echo "$IP_ADDRESS" | tr '.' '_')"
DEDUP_FILE="$QUEUE_BASE/.dedup-${ACTION}-${SAFE_IP}"
now=$(date +%s)
if [ -f "$DEDUP_FILE" ]; then
  last=$(cat "$DEDUP_FILE" 2>/dev/null || echo 0)
  if [ $((now - last)) -lt "$DEDUP_WINDOW" ]; then
    log "SKIP_DUP action=$ACTION ip=$IP_ADDRESS age_sec=$((now - last))"
    exit 0
  fi
fi
printf '%s' "$now" > "$DEDUP_FILE" 2>/dev/null || true

# Resolve VLAN and host offset using Kea config
MAP_OUT=""
if [ -n "$PYTHON_BIN" ] && [ -f "$KEA_CONFIG_PATH" ]; then
MAP_OUT=$($PYTHON_BIN - <<'PY' "$KEA_CONFIG_PATH" "$IP_ADDRESS"
import ipaddress
import json
import sys

config_path = sys.argv[1]
ip_str = sys.argv[2]

with open(config_path, 'r', encoding='utf-8') as handle:
  data = json.load(handle)

ip = ipaddress.ip_address(ip_str)

for entry in data.get('Dhcp4', {}).get('subnet4', []):
  try:
    vlan_id = int(entry.get('id'))
  except Exception:
    continue
  network = ipaddress.ip_network(entry.get('subnet'), strict=False)
  if ip in network:
    offset = int(ip) - int(network.network_address)
    print(f"VLAN_ID={vlan_id}")
    print(f"OFFSET={offset}")
    break
PY
  )
  fi

VLAN_ID="$(printf '%s\n' "$MAP_OUT" | awk -F= '/^VLAN_ID=/{print $2}')"
HOST_OFFSET="$(printf '%s\n' "$MAP_OUT" | awk -F= '/^OFFSET=/{print $2}')"

if [ -z "$VLAN_ID" ] || [ -z "$HOST_OFFSET" ]; then
  VLAN_ID="$(echo "$IP_ADDRESS" | awk -F. '{print $3}')"
  HOST_OFFSET="$(echo "$IP_ADDRESS" | awk -F. '{print $4}')"
fi

if [ -z "$VLAN_ID" ] || [ -z "$HOST_OFFSET" ]; then
  log "SKIP_INVALID action=$ACTION ip=$IP_ADDRESS reason=unknown_vlan"
  exit 0
fi

ACL_NUM=$((3000 + VLAN_ID * 10))
RULE_NUM=$((1000 + HOST_OFFSET))

SSH_TTY_FLAG="${SSH_TTY_FLAG:--tt}"  # Changed: Default to -tt for Comware
SSH_TTY_FALLBACK="${SSH_TTY_FALLBACK:-0}"  # Changed: Disable fallback
SSH_HOSTKEY_OPTS="${SSH_HOSTKEY_OPTS:--o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa}"
SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT $SSH_HOSTKEY_OPTS -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3"

run_ssh() {
  phase="$1"
  cmds="$2"
  tty_flag="$SSH_TTY_FLAG"
  temp_out=$(mktemp /tmp/ssh_out.XXXXXX)
  temp_err=$(mktemp /tmp/ssh_err.XXXXXX)

  set +e
  printf "%s\n" "$cmds" | ssh $tty_flag $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$temp_out" 2> "$temp_err"
  status=$?
  set -e

  if [ $status -ne 0 ]; then
    log "ERROR action=$ACTION phase=$phase status=$status stdout=$(cat "$temp_out") stderr=$(cat "$temp_err")"
  else
    log "SUCCESS action=$ACTION phase=$phase stdout=$(cat "$temp_out")"
  fi
  rm -f "$temp_out" "$temp_err"

  if [ $status -ne 0 ] && [ "$SSH_TTY_FALLBACK" = "1" ] && [ "$tty_flag" != "-tt" ]; then
    log "WARN action=$ACTION phase=$phase reason=ssh_failed status=$status retry_tty=-tt"
    temp_out=$(mktemp /tmp/ssh_out.XXXXXX)
    temp_err=$(mktemp /tmp/ssh_err.XXXXXX)
    set +e
    printf "%s\n" "$cmds" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$temp_out" 2> "$temp_err"
    status=$?
    set -e
    if [ $status -ne 0 ]; then
      log "ERROR_RETRY action=$ACTION phase=$phase status=$status stdout=$(cat "$temp_out") stderr=$(cat "$temp_err")"
    else
      log "SUCCESS_RETRY action=$ACTION phase=$phase stdout=$(cat "$temp_out")"
    fi
    rm -f "$temp_out" "$temp_err"
  fi

  return $status
}

if [ "$ACTION" = "block" ]; then
  CMDS_APPLY=$(cat <<EOF
system-view
acl advanced $ACL_NUM
rule $RULE_NUM deny ip source $IP_ADDRESS 0
quit
quit  
quit
EOF
)
  CMDS_SAVE=$(cat <<EOF
save force
quit  
EOF
)
elif [ "$ACTION" = "unblock" ]; then
  CMDS_APPLY=$(cat <<EOF
system-view
acl advanced $ACL_NUM
undo rule $RULE_NUM
quit
quit
quit  
EOF
)
  CMDS_SAVE=$(cat <<EOF
save force
quit  
EOF
)
else
  echo "Invalid action: $ACTION" >&2
  exit 1
fi

if [ "$QUEUE_DISABLE" = "1" ]; then
  # Execute commands via SSH (force TTY for Comware)
  apply_start=$(date +%s)
  log "START action=$ACTION phase=apply ip=$IP_ADDRESS vlan=$VLAN_ID acl=$ACL_NUM rule=$RULE_NUM host=$SWITCH_HOST"
  run_ssh "apply" "$CMDS_APPLY"
  apply_status=$?
  apply_end=$(date +%s)
  apply_duration=$((apply_end - apply_start))
  log "END action=$ACTION phase=apply ip=$IP_ADDRESS status=$apply_status duration_sec=$apply_duration"

  save_start=$(date +%s)
  log "START action=$ACTION phase=save ip=$IP_ADDRESS vlan=$VLAN_ID acl=$ACL_NUM rule=$RULE_NUM host=$SWITCH_HOST"
  run_ssh "save" "$CMDS_SAVE"
  save_status=$?
  save_end=$(date +%s)
  save_duration=$((save_end - save_start))
  log "END action=$ACTION phase=save ip=$IP_ADDRESS status=$save_status duration_sec=$save_duration"

  exit $save_status
fi

# Queue mode (default)
log "QUEUE action=$ACTION ip=$IP_ADDRESS vlan=$VLAN_ID acl=$ACL_NUM rule=$RULE_NUM"
mkdir -p "$(dirname "$QUEUE_FILE")" 2>/dev/null || true
printf '%s|%s|%s\n' "$(timestamp)" "$ACTION" "$IP_ADDRESS" >> "$QUEUE_FILE"

if [ -f "$QUEUE_PID_FILE" ] && kill -0 "$(cat "$QUEUE_PID_FILE" 2>/dev/null)" 2>/dev/null; then
  exit 0
fi

if [ -x "$QUEUE_WORKER" ]; then
  nohup "$QUEUE_WORKER" >/dev/null 2>&1 &
  echo $! > "$QUEUE_PID_FILE" 2>/dev/null || true
  log "QUEUE_WORKER_STARTED pid=$(cat "$QUEUE_PID_FILE" 2>/dev/null) interval_sec=$QUEUE_INTERVAL"
else
  log "QUEUE_WORKER_MISSING path=$QUEUE_WORKER"
fi
exit 0