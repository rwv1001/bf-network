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

SWITCH_HOST="$(printf '%s' "${SWITCH_HOSTS:-}" | awk '{print $1}')"
[ -n "$SWITCH_HOST" ] || { echo "SWITCH_HOSTS required" >&2; exit 1; }
SAFE_HOST="$(echo "${SWITCH_HOST}" | tr '.:' '__')"
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

LOG_FILE="${ACL_LOG_FILE:-$QUEUE_BASE/hp5130-acl-${SAFE_HOST}.log}"
QUEUE_FILE="${ACL_QUEUE_FILE:-$QUEUE_BASE/hp5130-acl-${SAFE_HOST}.queue}"
QUEUE_PID_FILE="${ACL_QUEUE_PID:-$QUEUE_BASE/hp5130-acl-${SAFE_HOST}.pid}"
QUEUE_INTERVAL="${ACL_QUEUE_INTERVAL:-3}"
QUEUE_DISABLE="${ACL_QUEUE_DISABLE:-0}"  # Corrected: Use ACL_QUEUE_DISABLE (was QUEUE_DISABLE in your command, but script checks this)
QUEUE_WORKER="${ACL_QUEUE_WORKER:-$SCRIPT_DIR/hp5130-acl-queue.sh}"
DEDUP_WINDOW="${ACL_DEDUP_WINDOW:-3}"
QUEUE_UMASK="${ACL_QUEUE_UMASK:-0002}"
QUEUE_GID="${ACL_QUEUE_GID:-}"
RULE_BASE="${ACL_RULE_BASE:-10000}"

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
DEDUP_FILE="$QUEUE_BASE/.dedup-${ACTION}-${SAFE_IP}-${SAFE_HOST}"
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

# Apply to both uplink ACLs (3951=UDM/Vlan1, 3953=TEL/Vlan2)
# Rule number: vlan_id * 150 + host_offset (unique across all VLANs, stays below 20000)
RULE_NUM=$((VLAN_ID * 150 + HOST_OFFSET))

# Safety: never add a per-IP rule for an IP already covered by a blanket
# blocked-pool range rule.  Blanket rules are added by hp5130-acl-baseline.sh
# (rule BLOCK_RULE_BASE+offset) and are authoritative for blocked-pool IPs;
# a redundant per-IP rule would outlive the lease and clutter the ACL.
if [ "$ACTION" = "block" ] && [ -n "$PYTHON_BIN" ] && [ -f "$KEA_CONFIG_PATH" ]; then
  _in_blocked_pool=$($PYTHON_BIN - <<'PY' "$KEA_CONFIG_PATH" "$IP_ADDRESS" 2>/dev/null
import ipaddress, json, sys
cfg, ip_str = sys.argv[1], sys.argv[2]
ip = ipaddress.ip_address(ip_str)
try:
    data = json.load(open(cfg))
except Exception:
    print('false'); sys.exit(0)
for subnet in data.get('Dhcp4', {}).get('subnet4', []):
    net = ipaddress.ip_network(subnet.get('subnet', ''), strict=False)
    if ip not in net:
        continue
    for pool in subnet.get('pools', []):
        if 'BLOCKED' in (pool.get('client-classes') or []):
            start, end = [p.strip() for p in pool['pool'].split('-')]
            for cidr in ipaddress.summarize_address_range(
                    ipaddress.ip_address(start), ipaddress.ip_address(end)):
                if ip in cidr:
                    print('true'); sys.exit(0)
    print('false'); sys.exit(0)
print('false')
PY
  )
  if [ "$_in_blocked_pool" = "true" ]; then
    log "SKIP_BLOCKED_POOL action=$ACTION ip=$IP_ADDRESS reason=covered_by_blanket_range"
    exit 0
  fi
fi

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
  CMDS=$(cat <<EOF
system-view
acl advanced 3951
rule $RULE_NUM deny ip source $IP_ADDRESS 0
quit
acl advanced 3953
rule $RULE_NUM deny ip source $IP_ADDRESS 0
quit
quit
save force
quit
EOF
)
elif [ "$ACTION" = "unblock" ]; then
  CMDS=$(cat <<EOF
system-view
acl advanced 3951
undo rule $RULE_NUM
quit
acl advanced 3953
undo rule $RULE_NUM
quit
quit
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
  log "START action=$ACTION phase=apply_save ip=$IP_ADDRESS vlan=$VLAN_ID acl=3951+3953 rule=$RULE_NUM host=$SWITCH_HOST"
  run_ssh "apply_save" "$CMDS"
  ssh_status=$?
  apply_end=$(date +%s)
  apply_duration=$((apply_end - apply_start))
  log "END action=$ACTION phase=apply_save ip=$IP_ADDRESS status=$ssh_status duration_sec=$apply_duration"

  exit $ssh_status
fi

# Queue mode (default)
log "QUEUE action=$ACTION ip=$IP_ADDRESS vlan=$VLAN_ID acl=3951+3953 rule=$RULE_NUM"
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