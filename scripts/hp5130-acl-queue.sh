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

# QUEUE_FILE, QUEUE_LOCK, QUEUE_PID_FILE, LOG_FILE are set below after
# SWITCH_HOST is established, so they can include a per-host suffix.
LOCK_STALE_SEC="${ACL_QUEUE_LOCK_STALE_SEC:-120}"
INTERVAL="${ACL_QUEUE_INTERVAL:-3}"
IDLE_MAX="${ACL_QUEUE_IDLE_MAX:-12}"
QUEUE_UMASK="${ACL_QUEUE_UMASK:-0002}"
QUEUE_GID="${ACL_QUEUE_GID:-}"
RULE_BASE="${ACL_RULE_BASE:-10000}"

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

SWITCH_HOST="$(printf '%s' "${SWITCH_HOSTS:-}" | awk '{print $1}')"
[ -n "$SWITCH_HOST" ] || { echo "SWITCH_HOSTS required" >&2; exit 1; }
SAFE_HOST="$(echo "${SWITCH_HOST}" | tr '.:' '__')"
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-$DEFAULT_KEY_PATH}"

# Per-host file paths — must agree with hp5130-acl.sh naming convention.
# If ACL_QUEUE_FILE/LOCK/PID/LOG are explicitly set in env, honour them;
# otherwise derive per-host defaults so that multiple workers for different
# switches can run concurrently without interfering with each other.
QUEUE_FILE="${ACL_QUEUE_FILE:-$QUEUE_BASE/hp5130-acl-${SAFE_HOST}.queue}"
QUEUE_LOCK="${ACL_QUEUE_LOCK:-$QUEUE_BASE/hp5130-acl-${SAFE_HOST}.lock}"
LOCK_META="${QUEUE_LOCK}/meta"
QUEUE_PID_FILE="${ACL_QUEUE_PID:-$QUEUE_BASE/hp5130-acl-${SAFE_HOST}.pid}"
LOG_FILE="${ACL_LOG_FILE:-$QUEUE_BASE/hp5130-acl-${SAFE_HOST}.log}"
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

  fail=0
  while IFS='|' read -r action ip; do
    [ -z "$action" ] && continue
    [ -z "$ip" ] && continue
    apply_start=$(date +%s)
    log "DISPATCH action=$action ip=$ip host=$SWITCH_HOST"
    set +e
    SWITCH_HOSTS="$SWITCH_HOST" \
    SWITCH_USER="$SWITCH_USER" \
    SWITCH_SSH_PORT="$SWITCH_SSH_PORT" \
    SWITCH_KEY_PATH="$SWITCH_KEY_PATH" \
    KEA_CONFIG_PATH="$KEA_CONFIG_PATH" \
    PYTHON_BIN="$PYTHON_BIN" \
    ACL_QUEUE_DIR="$QUEUE_BASE" \
    ACL_QUEUE_DISABLE=1 \
      "$SCRIPT_DIR/hp5130-acl.sh" "$action" "$ip"
    apply_status=$?
    set -e
    apply_end=$(date +%s)
    log "DISPATCH_END action=$action ip=$ip status=$apply_status duration_sec=$((apply_end - apply_start))"
    if [ "$apply_status" -ne 0 ]; then
      fail=1
    fi
  done < "$dedup"

  if [ "$fail" -ne 0 ]; then
    cat "$tmp" >> "$QUEUE_FILE"
    log "BATCH_REQUEUE reason=ssh_failure"
  fi

  rm -f "$tmp" "$dedup" 2>/dev/null || true
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