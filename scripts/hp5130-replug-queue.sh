#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

QUEUE_BASE="${REPLUG_QUEUE_DIR:-}"
if [ -z "$QUEUE_BASE" ]; then
  if [ -d "/acl-queue" ]; then
    QUEUE_BASE="/acl-queue"
  else
    QUEUE_BASE="$BASE_DIR/shared/acl-queue"
  fi
fi

QUEUE_FILE="${REPLUG_QUEUE_FILE:-$QUEUE_BASE/hp5130-replug.queue}"
QUEUE_LOCK="${REPLUG_QUEUE_LOCK:-$QUEUE_BASE/hp5130-replug.lock}"
LOCK_META="$QUEUE_LOCK/meta"
LOCK_STALE_SEC="${REPLUG_QUEUE_LOCK_STALE_SEC:-120}"
QUEUE_PID_FILE="${REPLUG_QUEUE_PID:-$QUEUE_BASE/hp5130-replug.pid}"
INTERVAL="${REPLUG_QUEUE_INTERVAL:-3}"
IDLE_MAX="${REPLUG_QUEUE_IDLE_MAX:-12}"
LOG_FILE="${REPLUG_LOG_FILE:-$QUEUE_BASE/hp5130-replug.log}"
QUEUE_UMASK="${REPLUG_QUEUE_UMASK:-0002}"
QUEUE_GID="${REPLUG_QUEUE_GID:-}"

umask "$QUEUE_UMASK" 2>/dev/null || true
mkdir -p "$QUEUE_BASE" 2>/dev/null || true
if [ -n "$QUEUE_GID" ]; then
  chgrp "$QUEUE_GID" "$QUEUE_BASE" 2>/dev/null || true
fi
chmod 2775 "$QUEUE_BASE" 2>/dev/null || true

REPLUG_SCRIPT="${SWITCH_REPLUG_SCRIPT:-$SCRIPT_DIR/hp5130-replug.sh}"

log() {
  printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*" >> "$LOG_FILE" 2>/dev/null || true
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

  tmp="/tmp/hp5130-replug.queue.$$"
  dedup="/tmp/hp5130-replug.dedup.$$"
  cp "$QUEUE_FILE" "$tmp"
  : > "$QUEUE_FILE"

  # Deduplicate: last entry per MAC wins, preserve last-seen order
  awk -F'|' 'NF>=3 {mac=$2; delay=$3; if (mac!="") {last[mac]=delay; order[++n]=mac}} END {for (i=1;i<=n;i++){mac=order[i]; if(!seen[mac]++){print mac "|" last[mac]}}}' "$tmp" > "$dedup"

  fail=0
  while IFS='|' read -r mac delay; do
    [ -z "$mac" ] && continue
    delay="${delay:-}"
    log "RUN mac=$mac delay=$delay"
    if [ -x "$REPLUG_SCRIPT" ]; then
      set +e
      out=$(REPLUG_QUEUE_DISABLE=1 "$REPLUG_SCRIPT" "$mac" "$delay" 2>&1)
      status=$?
      set -e
      log "RUN_DONE mac=$mac status=$status output=$(printf '%s' "$out" | tr '\n' ';')"
      if [ "$status" -ne 0 ]; then
        fail=1
      fi
    else
      log "ERROR reason=missing_script path=$REPLUG_SCRIPT"
      fail=1
    fi
  done < "$dedup"

  if [ "$fail" -ne 0 ]; then
    cat "$tmp" >> "$QUEUE_FILE"
    log "REQUEUE reason=run_failed"
  fi

  rm -f "$tmp" "$dedup" 2>/dev/null || true
}

idle=0
while :; do
  if ! acquire_lock; then
    sleep "$INTERVAL"
    continue
  fi

  process_queue
  rm -rf "$QUEUE_LOCK" 2>/dev/null || true

  if [ -s "$QUEUE_FILE" ]; then
    idle=0
  else
    idle=$((idle + 1))
  fi

  if [ "$idle" -ge "$IDLE_MAX" ]; then
    exit 0
  fi

  sleep "$INTERVAL"
done
