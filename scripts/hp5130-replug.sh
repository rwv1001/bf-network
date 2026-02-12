#!/bin/sh
set -eu

MAC_RAW="${1:-}"
DELAY_SEC="${2:-}"

if [ -z "$MAC_RAW" ]; then
  echo "Usage: $0 <mac_address> [delay_sec]" >&2
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

QUEUE_BASE="${REPLUG_QUEUE_DIR:-}"
if [ -z "$QUEUE_BASE" ]; then
  if [ -d "/acl-queue" ]; then
    QUEUE_BASE="/acl-queue"
  else
    QUEUE_BASE="$BASE_DIR/shared/acl-queue"
  fi
fi

LOG_FILE="${REPLUG_LOG_FILE:-$QUEUE_BASE/hp5130-replug.log}"
QUEUE_FILE="${REPLUG_QUEUE_FILE:-$QUEUE_BASE/hp5130-replug.queue}"
QUEUE_PID_FILE="${REPLUG_QUEUE_PID:-$QUEUE_BASE/hp5130-replug.pid}"
QUEUE_WORKER="${REPLUG_QUEUE_WORKER:-$SCRIPT_DIR/hp5130-replug-queue.sh}"
QUEUE_DISABLE="${REPLUG_QUEUE_DISABLE:-0}"
DEDUP_WINDOW="${REPLUG_DEDUP_WINDOW:-3}"
QUEUE_UMASK="${REPLUG_QUEUE_UMASK:-0002}"
QUEUE_GID="${REPLUG_QUEUE_GID:-}"

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

SSH_TTY_FLAG="${SSH_TTY_FLAG:--tt}"
SSH_TTY_FALLBACK="${SSH_TTY_FALLBACK:-0}"
SSH_HOSTKEY_OPTS="${SSH_HOSTKEY_OPTS:--o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa}"
SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT $SSH_HOSTKEY_OPTS -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3"

if [ -z "$DELAY_SEC" ]; then
  DELAY_SEC="${SWITCH_REPLUG_DELAY_SEC:-3}"
fi

if ! echo "$DELAY_SEC" | grep -Eq '^[0-9]+$'; then
  DELAY_SEC=3
fi
if [ "$DELAY_SEC" -lt 1 ]; then
  DELAY_SEC=1
fi

normalize_mac() {
  echo "$1" | tr -cd '0-9A-Fa-f' | tr 'a-f' 'A-F' | sed 's/\(..\)/\1-/g; s/-$//'
}

format_lookup_mac() {
  echo "$1" | tr -cd '0-9A-Fa-f' | tr 'A-F' 'a-f' | sed 's/\(....\)/\1-/g; s/-$//'
}

expand_iface() {
  case "$1" in
    GE*) echo "GigabitEthernet${1#GE}" ;;
    XGE*) echo "Ten-GigabitEthernet${1#XGE}" ;;
    *) echo "$1" ;;
  esac
}

run_ssh() {
  phase="$1"
  cmds="$2"
  tty_flag="$SSH_TTY_FLAG"
  tmp_out=$(mktemp /tmp/ssh_out.XXXXXX)
  tmp_err=$(mktemp /tmp/ssh_err.XXXXXX)

  set +e
  printf "%s\nquit\n" "$cmds" | ssh $tty_flag $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$tmp_out" 2> "$tmp_err"
  status=$?
  set -e

  if [ $status -ne 0 ] && [ "$SSH_TTY_FALLBACK" = "1" ] && [ "$tty_flag" != "-tt" ]; then
    set +e
    printf "%s\nquit\n" "$cmds" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" > "$tmp_out" 2> "$tmp_err"
    status=$?
    set -e
  fi

  if [ $status -ne 0 ]; then
    echo "ERROR phase=$phase status=$status stdout=$(cat "$tmp_out") stderr=$(cat "$tmp_err")" >&2
  fi

  rm -f "$tmp_out" "$tmp_err"
  return $status
}

MAC_NORM="$(normalize_mac "$MAC_RAW")"
if [ -z "$MAC_NORM" ] || [ "${#MAC_NORM}" -ne 17 ]; then
  echo "Invalid MAC: $MAC_RAW" >&2
  exit 2
fi
MAC_LOOKUP="$(format_lookup_mac "$MAC_RAW")"

SAFE_MAC="$(echo "$MAC_NORM" | tr ':' '_' | tr '-' '_')"
DEDUP_FILE="$QUEUE_BASE/.dedup-replug-${SAFE_MAC}"
now=$(date +%s)
if [ "${REPLUG_QUEUE_DISABLE:-0}" != "1" ]; then
  if [ -f "$DEDUP_FILE" ]; then
    last=$(cat "$DEDUP_FILE" 2>/dev/null || echo 0)
    if [ $((now - last)) -lt "$DEDUP_WINDOW" ]; then
      log "SKIP_DUP mac=$MAC_NORM age_sec=$((now - last))"
      exit 0
    fi
  fi
  printf '%s' "$now" > "$DEDUP_FILE" 2>/dev/null || true
fi

if [ "$QUEUE_DISABLE" != "1" ]; then
  log "QUEUE mac=$MAC_NORM delay=$DELAY_SEC"
  mkdir -p "$(dirname "$QUEUE_FILE")" 2>/dev/null || true
  printf '%s|%s|%s\n' "$(timestamp)" "$MAC_NORM" "$DELAY_SEC" >> "$QUEUE_FILE"

  if [ -f "$QUEUE_PID_FILE" ] && kill -0 "$(cat "$QUEUE_PID_FILE" 2>/dev/null)" 2>/dev/null; then
    exit 0
  fi

  if [ -x "$QUEUE_WORKER" ]; then
    nohup "$QUEUE_WORKER" >/dev/null 2>&1 &
    echo $! > "$QUEUE_PID_FILE" 2>/dev/null || true
    log "QUEUE_WORKER_STARTED pid=$(cat "$QUEUE_PID_FILE" 2>/dev/null)"
  else
    log "QUEUE_WORKER_MISSING path=$QUEUE_WORKER"
  fi
  exit 0
fi

log "DIRECT_RUN mac=$MAC_NORM delay=$DELAY_SEC"
log "SSH_LOOKUP_OPTS tty=$SSH_TTY_FLAG opts=$SSH_OPTS user=$SWITCH_USER host=$SWITCH_HOST"

LOOKUP_CMD="display mac-address | include $MAC_LOOKUP"
log "LOOKUP_BEGIN mac=$MAC_NORM cmd=$LOOKUP_CMD"
set +e
LOOKUP_OUT=$(printf '%s\nquit\n' "$LOOKUP_CMD" | ssh $SSH_TTY_FLAG $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" 2>&1)
LOOKUP_STATUS=$?
set -e
log "LOOKUP_DONE mac=$MAC_NORM status=$LOOKUP_STATUS"
printf '%s' "$LOOKUP_OUT" \
  | tr '\r' '\n' \
  | sed -E 's/;+$/;/; s/;+/\n/g' \
  | while IFS= read -r line; do
      [ -n "$line" ] && log "LOOKUP_OUT $line"
    done

if [ -z "$LOOKUP_OUT" ]; then
  LOOKUP_CMD="display mac-address dynamic | include $MAC_LOOKUP"
  log "LOOKUP_BEGIN mac=$MAC_NORM cmd=$LOOKUP_CMD"
  set +e
  LOOKUP_OUT=$(printf '%s\nquit\n' "$LOOKUP_CMD" | ssh $SSH_TTY_FLAG $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" 2>&1)
  LOOKUP_STATUS=$?
  set -e
  log "LOOKUP_DONE mac=$MAC_NORM status=$LOOKUP_STATUS"
  printf '%s' "$LOOKUP_OUT" \
    | tr '\r' '\n' \
    | sed -E 's/;+$/;/; s/;+/\n/g' \
    | while IFS= read -r line; do
        [ -n "$line" ] && log "LOOKUP_OUT $line"
      done
fi

MAC_NO_DASH=$(echo "$MAC_NORM" | tr -d '-')
IFACE=$(printf '%s\n' "$LOOKUP_OUT" | awk -v mac="$MAC_NO_DASH" '
  {
    field = toupper($1);
    gsub(/[-]/, "", field);
    if (field == mac) {
      print $4;
      exit;
    }
  }
')
IFACE=$(expand_iface "$IFACE")
log "LOOKUP_IFACE mac=$MAC_NORM iface=$IFACE"

if [ -z "$IFACE" ]; then
  echo "Unable to locate interface for $MAC_NORM" >&2
  exit 3
fi

CMDS_DOWN=$(cat <<EOF
system-view
interface $IFACE
shutdown
quit
quit
quit
EOF
)
CMDS_UP=$(cat <<EOF
system-view
interface $IFACE
undo shutdown
quit
quit
quit
EOF
)

run_ssh "down" "$CMDS_DOWN"
status=$?
if [ $status -ne 0 ]; then
  exit $status
fi

sleep "$DELAY_SEC"
run_ssh "up" "$CMDS_UP"
