#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

QUEUE_BASE="${ACL_QUEUE_DIR:-}"
if [ -z "$QUEUE_BASE" ]; then
  if [ -d "/acl-queue" ]; then
    QUEUE_BASE="/acl-queue"
  else
    QUEUE_BASE="$BASE_DIR/shared/acl-queue"
  fi
fi

QUEUE_FILE="${ACL_QUEUE_FILE:-$QUEUE_BASE/hp5130-acl.queue}"
QUEUE_LOCK="${ACL_QUEUE_LOCK:-$QUEUE_BASE/hp5130-acl.lock}"
LOCK_META="${QUEUE_LOCK}/meta"
LOCK_STALE_SEC="${ACL_QUEUE_LOCK_STALE_SEC:-120}"
QUEUE_PID_FILE="${ACL_QUEUE_PID:-$QUEUE_BASE/hp5130-acl.pid}"
INTERVAL="${ACL_QUEUE_INTERVAL:-3}"
IDLE_MAX="${ACL_QUEUE_IDLE_MAX:-12}"
LOG_FILE="${ACL_LOG_FILE:-$QUEUE_BASE/hp5130-acl.log}"
QUEUE_UMASK="${ACL_QUEUE_UMASK:-0002}"
QUEUE_GID="${ACL_QUEUE_GID:-}"

umask "$QUEUE_UMASK" 2>/dev/null || true
if [ -n "$QUEUE_GID" ]; then
  chgrp "$QUEUE_GID" "$QUEUE_BASE" 2>/dev/null || true
fi
chmod 2775 "$QUEUE_BASE" 2>/dev/null || true
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

SSH_TTY_FLAG="${SSH_TTY_FLAG:--tt}"  # Changed: Default to -tt for Comware compatibility
SSH_TTY_FALLBACK="${SSH_TTY_FALLBACK:-0}"  # Changed: Disable fallback, as -tt is reliable
SSH_HOSTKEY_OPTS="${SSH_HOSTKEY_OPTS:--o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa}"
SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT $SSH_HOSTKEY_OPTS -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3"

timestamp() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}

log() {
  printf '%s %s\n' "$(timestamp)" "$*" >> "$LOG_FILE" 2>/dev/null || true
}

run_ssh_cmdfile() {
  phase="$1"
  cmd_file="$2"
  tty_flag="$SSH_TTY_FLAG"
  temp_out=$(mktemp /tmp/ssh_out.XXXXXX)
  temp_err=$(mktemp /tmp/ssh_err.XXXXXX)

  set +e
  cat "$cmd_file" | ssh $tty_flag $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$temp_out" 2> "$temp_err"
  status=$?
  set -e

  if [ $status -ne 0 ]; then
    log "ERROR phase=$phase status=$status stdout=$(cat "$temp_out") stderr=$(cat "$temp_err")"
  else
    log "SUCCESS phase=$phase stdout=$(cat "$temp_out")"
  fi
  rm -f "$temp_out" "$temp_err"

  if [ $status -ne 0 ] && [ "$SSH_TTY_FALLBACK" = "1" ] && [ "$tty_flag" != "-tt" ]; then
    log "WARN phase=$phase reason=ssh_failed status=$status retry_tty=-tt"
    temp_out=$(mktemp /tmp/ssh_out.XXXXXX)
    temp_err=$(mktemp /tmp/ssh_err.XXXXXX)
    set +e
    cat "$cmd_file" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$temp_out" 2> "$temp_err"
    status=$?
    set -e
    if [ $status -ne 0 ]; then
      log "ERROR_RETRY phase=$phase status=$status stdout=$(cat "$temp_out") stderr=$(cat "$temp_err")"
    else
      log "SUCCESS_RETRY phase=$phase stdout=$(cat "$temp_out")"
    fi
    rm -f "$temp_out" "$temp_err"
  fi

  return $status
}

cleanup() {
  rm -f "$QUEUE_PID_FILE" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

lock_is_stale() {
  [ -f "$LOCK_META" ] || return 0
  pid=$(cut -d'|' -f1 "$LOCK_META" 2>/dev/null || echo "")
  ts=$(cut -d'|' -f2 "$LOCK_META" 2>/dev/null || echo "")
  now=$(date +%s)

  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    return 1
  fi

  if [ -n "$ts" ]; then
    age=$((now - ts))
    [ "$age" -ge "$LOCK_STALE_SEC" ] && return 0
  fi

  return 0
}

acquire_lock() {
  if mkdir "$QUEUE_LOCK" 2>/dev/null; then
    echo "$$|$(date +%s)" > "$LOCK_META" 2>/dev/null || true
    return 0
  fi

  if lock_is_stale; then
    rm -rf "$QUEUE_LOCK" 2>/dev/null || true
    if mkdir "$QUEUE_LOCK" 2>/dev/null; then
      echo "$$|$(date +%s)" > "$LOCK_META" 2>/dev/null || true
      return 0
    fi
  fi

  return 1
}

process_queue() {
  [ -s "$QUEUE_FILE" ] || return 0

  tmp="/tmp/hp5130-acl.queue.$$"
  dedup="/tmp/hp5130-acl.dedup.$$"
  cp "$QUEUE_FILE" "$tmp"
  : > "$QUEUE_FILE"

  # Deduplicate: last action per IP wins, preserve last-seen order
  awk -F'|' 'NF>=3 {action=$2; ip=$3; if (ip!="") {last[ip]=action; order[++n]=ip}} END {for (i=1;i<=n;i++){ip=order[i]; if(!seen[ip]++){print last[ip] "|" ip}}}' "$tmp" > "$dedup"

  for vlan in 10 20 30 40 50 60 70 80 90 99; do
    : > "/tmp/hp5130-acl.${vlan}.$$"
  done

  while IFS='|' read -r action ip; do
    [ -z "$action" ] && continue
    [ -z "$ip" ] && continue
    map_out=""
    if [ -n "$PYTHON_BIN" ] && [ -f "$KEA_CONFIG_PATH" ]; then
    map_out=$($PYTHON_BIN - <<'PY' "$KEA_CONFIG_PATH" "$ip"
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
    vlan=$(printf '%s\n' "$map_out" | awk -F= '/^VLAN_ID=/{print $2}')
    host=$(printf '%s\n' "$map_out" | awk -F= '/^OFFSET=/{print $2}')
    if [ -z "$vlan" ] || [ -z "$host" ]; then
      vlan=$(echo "$ip" | awk -F. '{print $3}')
      host=$(echo "$ip" | awk -F. '{print $4}')
    fi
    [ -z "$vlan" ] && continue
    [ -z "$host" ] && continue
    echo "$action|$ip|$host" >> "/tmp/hp5130-acl.${vlan}.$$"
  done < "$dedup"

  fail=0
  for vlan in 10 20 30 40 50 60 70 80 90 99; do
    vlan_file="/tmp/hp5130-acl.${vlan}.$$"
    [ -s "$vlan_file" ] || continue
    acl=$((3000 + vlan * 10))

    apply_start=$(date +%s)
    log "BATCH_START phase=apply vlan=$vlan acl=$acl host=$SWITCH_HOST"
    cmd_file="/tmp/hp5130-acl.cmd.${vlan}.$$"
    {
      echo "system-view"
      echo "acl advanced $acl"
      while IFS='|' read -r action ip host; do
        rule=$((1000 + host))
        if [ "$action" = "block" ]; then
          echo "rule $rule deny ip source $ip 0"
        else
          echo "undo rule $rule"
        fi
      done < "$vlan_file"
      echo "quit"
      echo "quit"
      echo "quit"  # Added: Extra quit to log out from user-view and close session
    } > "$cmd_file"
    run_ssh_cmdfile "apply" "$cmd_file"
    apply_status=$?
    apply_end=$(date +%s)
    apply_duration=$((apply_end - apply_start))
    log "BATCH_END phase=apply vlan=$vlan status=$apply_status duration_sec=$apply_duration"

    save_start=$(date +%s)
    log "BATCH_START phase=save vlan=$vlan host=$SWITCH_HOST"
    {
      echo "save force"
      echo "quit"  # Added: Quit to close session after save
    } > "$cmd_file"
    run_ssh_cmdfile "save" "$cmd_file"
    save_status=$?
    save_end=$(date +%s)
    save_duration=$((save_end - save_start))
    log "BATCH_END phase=save vlan=$vlan status=$save_status duration_sec=$save_duration"

    if [ "$apply_status" -ne 0 ] || [ "$save_status" -ne 0 ]; then
      fail=1
    fi
  done

  if [ "$fail" -ne 0 ]; then
    cat "$tmp" >> "$QUEUE_FILE"
    log "BATCH_REQUEUE reason=ssh_failure"
  fi

  rm -f "$tmp" "$dedup" /tmp/hp5130-acl.*.$$ /tmp/hp5130-acl.cmd.*.$$ 2>/dev/null || true
  return 0
}

idle_count=0
while true; do
  did_work=0
  if acquire_lock; then
    trap 'rm -rf "$QUEUE_LOCK" 2>/dev/null || true' EXIT INT TERM
    if [ -s "$QUEUE_FILE" ]; then
      process_queue
      did_work=1
    fi
    rm -rf "$QUEUE_LOCK" 2>/dev/null || true
  fi

  if [ "$did_work" -eq 1 ]; then
    idle_count=0
  else
    idle_count=$((idle_count + 1))
  fi

  if [ "$idle_count" -ge "$IDLE_MAX" ]; then
    log "QUEUE_WORKER_EXIT idle_cycles=$idle_count"
    exit 0
  fi

  sleep "$INTERVAL"
done