#!/bin/sh
set -eu

MODE="normal"
ACTION=""
IP_ADDRESS=""

case "${1:-}" in
  --worker)
    MODE="worker"
    ;;
  --apply)
    MODE="apply"
    ACTION="${2:-}"
    IP_ADDRESS="${3:-}"
    ;;
  -h|--help)
    echo "Usage: $0 {block|unblock} <ip_address> | --worker | --apply {block|unblock} <ip_address>" >&2
    exit 0
    ;;
  *)
    MODE="normal"
    ACTION="${1:-}"
    IP_ADDRESS="${2:-}"
    ;;
esac

if [ "$MODE" != "worker" ]; then
  if [ -z "$ACTION" ] || [ -z "$IP_ADDRESS" ]; then
    echo "Usage: $0 {block|unblock} <ip_address> | --worker | --apply {block|unblock} <ip_address>" >&2
    exit 1
  fi
  case "$ACTION" in
    block|unblock) ;;
    *) echo "Invalid action: $ACTION" >&2; exit 1 ;;
  esac
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SELF_SCRIPT="$SCRIPT_DIR/$(basename "$0")"
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
QUEUE_DISABLE="${ACL_QUEUE_DISABLE:-${QUEUE_DISABLE:-0}}"
if [ "$MODE" = "apply" ]; then
  QUEUE_DISABLE="1"
fi
ACL_QUEUE_DISABLE="$QUEUE_DISABLE"
QUEUE_LOCK="${ACL_QUEUE_LOCK:-$QUEUE_BASE/hp5130-acl-${SAFE_HOST}.lock}"
LOCK_META="$QUEUE_LOCK/meta"
LOCK_STALE_SEC="${ACL_QUEUE_LOCK_STALE_SEC:-120}"
IDLE_MAX="${ACL_QUEUE_IDLE_MAX:-12}"
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

janitor() {
  # Hourly housekeeping: dedup stamps only matter for DEDUP_WINDOW seconds,
  # and the append-only logs would otherwise grow without bound.
  marker="$QUEUE_BASE/.janitor-last"
  now_j=$(date +%s)
  if [ -f "$marker" ]; then
    last_j=$(cat "$marker" 2>/dev/null || echo 0)
    case "$last_j" in *[!0-9]*) last_j=0 ;; esac
    [ $((now_j - last_j)) -lt 3600 ] && return 0
  fi
  echo "$now_j" > "$marker" 2>/dev/null || return 0
  find "$QUEUE_BASE" -maxdepth 1 -name '.dedup-*' -mtime +0 -delete 2>/dev/null || true
  for lf in "$QUEUE_BASE"/*.log; do
    [ -f "$lf" ] || continue
    sz=$(wc -c < "$lf" 2>/dev/null || echo 0)
    case "$sz" in *[!0-9]*) continue ;; esac
    if [ "$sz" -gt "${ACL_LOG_MAX_BYTES:-1048576}" ]; then
      mv -f "$lf" "$lf.1" 2>/dev/null || true
    fi
  done
}
janitor

enqueue_and_start_worker() {
  log "QUEUE action=$ACTION ip=$IP_ADDRESS host=$SWITCH_HOST"

  mkdir -p "$(dirname "$QUEUE_FILE")" 2>/dev/null || true

  (
    flock -x 9 || exit 1
    printf '%s|%s|%s\n' "$(timestamp)" "$ACTION" "$IP_ADDRESS" >> "$QUEUE_FILE"

    if [ -f "$QUEUE_PID_FILE" ] && kill -0 "$(cat "$QUEUE_PID_FILE" 2>/dev/null)" 2>/dev/null; then
      exit 0
    fi

    nohup "$SELF_SCRIPT" --worker >/dev/null 2>&1 &
    echo $! > "$QUEUE_PID_FILE" 2>/dev/null || true
    log "QUEUE_WORKER_STARTED pid=$(cat "$QUEUE_PID_FILE" 2>/dev/null) interval_sec=$QUEUE_INTERVAL"
  ) 9>"$QUEUE_FILE.lock"
}

cleanup_worker_pid() {
  if [ -f "$QUEUE_PID_FILE" ] && [ "$(cat "$QUEUE_PID_FILE" 2>/dev/null)" = "$$" ]; then
    rm -f "$QUEUE_PID_FILE" 2>/dev/null || true
  fi
}

lock_is_stale() {
  [ -f "$LOCK_META" ] || return 0

  pid=$(cut -d'|' -f1 "$LOCK_META" 2>/dev/null || echo "")
  ts=$(cut -d'|' -f2 "$LOCK_META" 2>/dev/null || echo "")
  now_lock=$(date +%s)

  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    return 1
  fi

  if [ -n "$ts" ]; then
    age=$((now_lock - ts))
    [ "$age" -ge "$LOCK_STALE_SEC" ] && return 0
  fi

  return 0
}

acquire_queue_lock() {
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

release_queue_lock() {
  rm -rf "$QUEUE_LOCK" 2>/dev/null || true
}

process_queue_once() {
  [ -s "$QUEUE_FILE" ] || return 0

  tmp="/tmp/hp5130-acl.queue.$$"
  dedup="/tmp/hp5130-acl.dedup.$$"
  failed="/tmp/hp5130-acl.failed.$$"

  cp "$QUEUE_FILE" "$tmp"
  : > "$QUEUE_FILE"
  : > "$failed"

  # Last action per IP wins, preserving the order of each IP's final occurrence.
  awk -F'|' '
    NF>=3 {
      action=$2; ip=$3
      if (ip != "") {
        last[ip]=action
        last_order[ip]=NR
      }
    }
    END {
      for (ip in last) print last_order[ip] "|" last[ip] "|" ip
    }
  ' "$tmp" | sort -n | awk -F'|' '{print $2 "|" $3}' > "$dedup"

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
    ACL_QUEUE_FILE="$QUEUE_FILE" \
    ACL_QUEUE_PID="$QUEUE_PID_FILE" \
    ACL_LOG_FILE="$LOG_FILE" \
    ACL_QUEUE_DISABLE=1 \
    QUEUE_DISABLE=1 \
      "$SELF_SCRIPT" --apply "$action" "$ip"
    apply_status=$?
    set -e

    apply_end=$(date +%s)
    log "DISPATCH_END action=$action ip=$ip status=$apply_status duration_sec=$((apply_end - apply_start))"

    if [ "$apply_status" -ne 0 ]; then
      printf '%s|%s|%s\n' "$(timestamp)" "$action" "$ip" >> "$failed"
    fi
  done < "$dedup"

  if [ -s "$failed" ]; then
    cat "$failed" >> "$QUEUE_FILE"
    log "BATCH_REQUEUE_FAILED_ONLY count=$(wc -l < "$failed" | tr -d '[:space:]')"
  fi

  rm -f "$tmp" "$dedup" "$failed" 2>/dev/null || true
  return 0
}

run_worker() {
  trap 'release_queue_lock; cleanup_worker_pid' EXIT INT TERM
  log "QUEUE_WORKER_RUNNING pid=$$ interval_sec=$QUEUE_INTERVAL"

  idle_count=0
  while true; do
    did_work=0

    if acquire_queue_lock; then
      if [ -s "$QUEUE_FILE" ]; then
        process_queue_once
        did_work=1
      fi
      release_queue_lock
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

    sleep "$QUEUE_INTERVAL"
  done
}

is_valid_ip() {
  echo "$1" | awk -F. 'NF==4 && $1>=0 && $1<=255 && $2>=0 && $2<=255 && $3>=0 && $3<=255 && $4>=0 && $4<=255 {exit 0} {exit 1}'
}

if [ "$MODE" = "worker" ]; then
  run_worker
  exit 0
fi

if ! is_valid_ip "$IP_ADDRESS"; then
  log "SKIP_INVALID action=$ACTION ip=$IP_ADDRESS"
  exit 0
fi

# ------------------------------------------------------------------
# Deduplication with detailed debug logging
# ------------------------------------------------------------------
SAFE_IP="$(echo "$IP_ADDRESS" | tr '.' '_')"
DEDUP_FILE="$QUEUE_BASE/.dedup-${ACTION}-${SAFE_IP}-${SAFE_HOST}"
now=$(date +%s)

log "DEDUP: === START ==="
log "DEDUP: ACTION=$ACTION IP=$IP_ADDRESS"
log "DEDUP: now=$now (from date +%s)"
log "DEDUP: DEDUP_FILE=$DEDUP_FILE"
log "DEDUP: DEDUP_WINDOW=$DEDUP_WINDOW"
log "DEDUP: ACL_QUEUE_DISABLE=$QUEUE_DISABLE"

if [ "$QUEUE_DISABLE" != "1" ]; then
  DEDUP_RC=0

  set +e
  (
    flock -x 8 || exit 2

    if [ -f "$DEDUP_FILE" ]; then
      raw_content=$(cat "$DEDUP_FILE" 2>/dev/null)
      log "DEDUP: raw file content = '$raw_content'"

      last=$(printf '%s' "$raw_content" | tr -d '[:space:]')
      log "DEDUP: last (after cleanup) = '$last'"

      if [ -n "$last" ] && [ "$last" -eq "$last" ] 2>/dev/null; then
        age=$((now - last))
        log "DEDUP: calculated age = $age seconds"

        if [ "$age" -lt "$DEDUP_WINDOW" ]; then
          log "SKIP_DUP action=$ACTION ip=$IP_ADDRESS age_sec=$age within_window=$DEDUP_WINDOW"
          log "DEDUP: === SKIP ==="
          exit 100
        fi

        log "DEDUP: age ($age) >= DEDUP_WINDOW ($DEDUP_WINDOW) - proceeding"
      else
        log "DEDUP: WARNING - could not parse last as integer. last='$last'"
      fi
    else
      log "DEDUP: file does not exist - will create new one"
    fi

    printf '%s\n' "$now" > "$DEDUP_FILE" 2>/dev/null || exit 3
    log "DEDUP: wrote new timestamp $now to dedup file"
    exit 0
  ) 8>"$DEDUP_FILE.lock"
  DEDUP_RC=$?
  set -e

  case "$DEDUP_RC" in
    0)
      log "DEDUP: === END ==="
      enqueue_and_start_worker
      exit 0
      ;;
    100)
      log "DEDUP: === END ==="
      exit 0
      ;;
    *)
      log "DEDUP: ERROR rc=$DEDUP_RC action=$ACTION ip=$IP_ADDRESS"
      log "DEDUP: === END ==="
      exit 1
      ;;
  esac
else
  log "DEDUP: ACL_QUEUE_DISABLE=1 - authoritative execution, skipping dedup and queue"
  log "DEDUP: === END ==="
fi

# ------------------------------------------------------------------
# Resolve VLAN ID and host offset using Kea config (with debug)
# ------------------------------------------------------------------
MAP_OUT=""
VLAN_ID=""
HOST_OFFSET=""

log "VLAN_RESOLVE: Starting VLAN lookup for IP=$IP_ADDRESS"
log "VLAN_RESOLVE: PYTHON_BIN=${PYTHON_BIN:-<empty>}"
log "VLAN_RESOLVE: KEA_CONFIG_PATH=${KEA_CONFIG_PATH:-<empty>}"

if [ -n "$PYTHON_BIN" ] && [ -f "$KEA_CONFIG_PATH" ]; then
    log "VLAN_RESOLVE: [BRANCH] Python available and Kea config exists → running Python lookup"

    MAP_OUT=$(
      "$PYTHON_BIN" - "$KEA_CONFIG_PATH" "$IP_ADDRESS" 2>&1 <<'PY'
import ipaddress
import json
import sys

config_path = sys.argv[1]
ip_str = sys.argv[2]

try:
    with open(config_path, 'r', encoding='utf-8') as handle:
        data = json.load(handle)
except Exception as e:
    print(f"ERROR=failed_to_read_kea_config:{e}")
    sys.exit(1)

ip = ipaddress.ip_address(ip_str)
found = False

for entry in data.get('Dhcp4', {}).get('subnet4', []):
    try:
        vlan_id = int(entry.get('id'))
    except Exception:
        continue

    try:
        network = ipaddress.ip_network(entry.get('subnet'), strict=False)
    except Exception:
        continue

    if ip in network:
        offset = int(ip) - int(network.network_address)
        print(f"VLAN_ID={vlan_id}")
        print(f"OFFSET={offset}")
        found = True
        break

if not found:
    print("ERROR=no_matching_subnet_found")
PY
)

    log "VLAN_RESOLVE: Python output = '$MAP_OUT'"

    # Parse the output
    VLAN_ID="$(printf '%s\n' "$MAP_OUT" | awk -F= '/^VLAN_ID=/{print $2}')"
    HOST_OFFSET="$(printf '%s\n' "$MAP_OUT" | awk -F= '/^OFFSET=/{print $2}')"

    if [ -n "$VLAN_ID" ] && [ -n "$HOST_OFFSET" ]; then
        log "VLAN_RESOLVE: [SUCCESS] VLAN_ID=$VLAN_ID HOST_OFFSET=$HOST_OFFSET"
    else
        log "VLAN_RESOLVE: [WARNING] Could not parse VLAN_ID or HOST_OFFSET from Python output"
    fi

else
    log "VLAN_RESOLVE: [ELSE] Python not available or Kea config missing"
    log "VLAN_RESOLVE: Falling back to parsing IP address manually"

    # Fallback parsing from IP address
    VLAN_ID="$(echo "$IP_ADDRESS" | awk -F. '{print $3}')"
    HOST_OFFSET="$(echo "$IP_ADDRESS" | awk -F. '{print $4}')"

    if [ -n "$VLAN_ID" ] && [ -n "$HOST_OFFSET" ]; then
        log "VLAN_RESOLVE: [FALLBACK SUCCESS] VLAN_ID=$VLAN_ID HOST_OFFSET=$HOST_OFFSET (parsed from IP)"
    else
        log "VLAN_RESOLVE: [FALLBACK FAILED] Could not parse VLAN_ID/HOST_OFFSET from IP=$IP_ADDRESS"
    fi
fi

# Final validation
if [ -z "$VLAN_ID" ] || [ -z "$HOST_OFFSET" ]; then
    log "SKIP_INVALID action=$ACTION ip=$IP_ADDRESS reason=unknown_vlan_or_offset"
    exit 0
fi


# ------------------------------------------------------------------
# Determine correct router uplink ACL from hp5130-policy.json
# ------------------------------------------------------------------
log "ACL_LOOKUP: Starting ACL lookup for VLAN_ID=$VLAN_ID"

POLICY_JSON="${HP5130_POLICY_PATH:-/scripts/scriptdata/hp5130-policy.json}"
ACL_NUM=""

log "ACL_LOOKUP: POLICY_JSON=$POLICY_JSON"
log "ACL_LOOKUP: PYTHON_BIN=${PYTHON_BIN:-<empty>}"

if [ -n "$PYTHON_BIN" ] && [ -f "$POLICY_JSON" ] && [ -n "$VLAN_ID" ]; then
    log "ACL_LOOKUP: [BRANCH] Entering Python lookup path"

    ACL_NUM=$(
        "$PYTHON_BIN" - "$POLICY_JSON" "$VLAN_ID" 2>&1 <<'PY'
import json
import sys

policy_path = sys.argv[1]
target_vlan = int(sys.argv[2])

with open(policy_path, 'r', encoding='utf-8') as f:
    policy = json.load(f)

# Step 1: Find the VLAN entry
vlan_entry = None
for v in policy.get('vlans', []):
    if int(v.get('vlan_id', 0)) == target_vlan:
        vlan_entry = v
        break

if not vlan_entry:
    print("ERROR=no_vlan_entry")
    sys.exit(0)

# Step 2: Get isp_router_id (with fallback)
isp_router_id = vlan_entry.get('isp_router_id')
if isp_router_id is None:
    isp_router_id = vlan_entry.get('resolved_isp_router_id') or 1

isp_router_id = int(isp_router_id)
print(f"DEBUG_ISP_ROUTER_ID={isp_router_id}")

# Step 3: Find router and return uplink_acl
for router in policy.get('routers', []):
    if int(router.get('id', 0)) == isp_router_id:
        acl = router.get('uplink_acl')
        if acl:
            print(acl)
            sys.exit(0)

print("ERROR=no_matching_router")
PY
    )

    log "ACL_LOOKUP: Python output = '$ACL_NUM'"

    # Clean up in case Python printed debug lines
    ACL_NUM=$(printf '%s\n' "$ACL_NUM" | grep -v '^DEBUG_' | tail -1 | tr -d '[:space:]')

    if [ -n "$ACL_NUM" ] && [ "$ACL_NUM" -eq "$ACL_NUM" ] 2>/dev/null; then
        log "ACL_LOOKUP: [SUCCESS] ACL_NUM=$ACL_NUM for VLAN_ID=$VLAN_ID"
    else
        log "ACL_LOOKUP: [WARNING] Invalid or empty ACL_NUM returned"
        ACL_NUM=""
    fi

else
    log "ACL_LOOKUP: [ELSE] Python, policy file, or VLAN_ID missing"
    ACL_NUM=""
fi

if [ -z "$ACL_NUM" ]; then
    log "ERROR: Could not determine uplink_acl for VLAN $VLAN_ID from policy"
    ACL_NUM=""
fi





if [ -z "$VLAN_ID" ] || [ -z "$HOST_OFFSET" ]; then
  VLAN_ID="$(echo "$IP_ADDRESS" | awk -F. '{print $3}')"
  HOST_OFFSET="$(echo "$IP_ADDRESS" | awk -F. '{print $4}')"
fi

if [ -z "$VLAN_ID" ] || [ -z "$HOST_OFFSET" ]; then
  log "SKIP_INVALID action=$ACTION ip=$IP_ADDRESS reason=unknown_vlan"
  exit 0
fi

# ---------------------------------------------------------------------------
# Rule number allocation
# Prefer a database-backed allocation (unique per IP, reuses freed numbers,
# guaranteed to stay below 20000).  Falls back to the arithmetic formula if
# DATABASE_URL is unavailable (e.g. running outside Docker without .env).
# ---------------------------------------------------------------------------
RULE_NUM=""
PSQL_BIN="$(command -v psql 2>/dev/null || true)"
DB_URL="${DATABASE_URL:-}"

if [ -n "$PSQL_BIN" ] && [ -n "$DB_URL" ]; then
  if [ "$ACTION" = "block" ]; then
    # Allocate lowest available rule number (RULE_BASE–19999) for this IP, or
    # return the existing one if the IP is already in the table.
    # Starting at RULE_BASE (default 10000) ensures dynamic per-IP deny rules
    # never collide with static baseline rules (portal permit at rule 5,
    # VLAN deny rules at 10–50, DoH/DoT rules at lower hundreds).
    _psql_out=$(
      "$PSQL_BIN" "$DB_URL" -t -A 2>/dev/null << EOSQL
BEGIN;
SELECT pg_advisory_xact_lock(88001);
INSERT INTO acl_rule_allocations (ip_address, rule_num)
SELECT '${IP_ADDRESS}', COALESCE(
    (SELECT MIN(n) FROM generate_series(${RULE_BASE}, 19999) n
     WHERE n NOT IN (SELECT rule_num FROM acl_rule_allocations)),
    -1
)
ON CONFLICT (ip_address) DO UPDATE
    SET allocated_at = NOW()
RETURNING rule_num;
COMMIT;
EOSQL
    )
    RULE_NUM=$(printf '%s\n' "$_psql_out" | grep -E '^[0-9]+$' | tail -1)
    if [ -z "$RULE_NUM" ] || [ "$RULE_NUM" = "-1" ]; then
      log "WARN action=$ACTION ip=$IP_ADDRESS reason=rule_alloc_failed fallback=formula"
      RULE_NUM=""
    fi
  else
    # Look up the previously allocated rule number for this IP.
    RULE_NUM=$(
      "$PSQL_BIN" "$DB_URL" -t -A \
        -c "SELECT rule_num FROM acl_rule_allocations WHERE ip_address = '${IP_ADDRESS}';" \
        2>/dev/null | grep -E '^[0-9]+$' | tail -1
    )
    if [ -z "$RULE_NUM" ]; then
      log "WARN action=$ACTION ip=$IP_ADDRESS reason=no_rule_alloc_found fallback=formula"
    fi
  fi
fi

# Formula fallback (VLAN_ID * 150 + HOST_OFFSET is unique for the standard
# VLAN set but may collide when VLAN IDs exceed ~133 or subnets are large).
if [ -z "$RULE_NUM" ]; then
  RULE_NUM=$((VLAN_ID * 150 + HOST_OFFSET))
fi

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
    log "ERROR action=$ACTION phase=$phase status=$status"
    log "       stdout: $(cat "$temp_out")"
    log "       stderr: $(cat "$temp_err")"
  else
    log "SUCCESS action=$ACTION phase=$phase"
    # Only log stdout if it's non-empty (to avoid noise)
    if [ -s "$temp_out" ]; then
        log "       stdout: $(cat "$temp_out")"
    fi
  fi
  rm -f "$temp_out" "$temp_err"

  return $status
}

log "APPLY action=$ACTION ip=$IP_ADDRESS vlan=$VLAN_ID acl=${ACL_NUM} rule=$RULE_NUM host=$SWITCH_HOST"

if [ "$ACTION" = "block" ]; then
  CMDS=$(cat <<EOF
system-view
acl advanced ${ACL_NUM}
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
acl advanced ${ACL_NUM}
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


# ------------------------------------------------------------------
# DEBUG: Show exactly what we are about to send to the switch
# ------------------------------------------------------------------
log "DEBUG: Final ACL_NUM resolved = ${ACL_NUM:-<NONE>}"
log "DEBUG: Commands being sent for action=$ACTION ip=$IP_ADDRESS:"

# Log each line of the command block
printf '%s\n' "$CMDS" | while IFS= read -r line || [ -n "$line" ]; do
    log "    $line"
done


if [ "$QUEUE_DISABLE" = "1" ]; then
  # Execute commands via SSH (force TTY for Comware)
  apply_start=$(date +%s)
  log "START action=$ACTION phase=apply_save ip=$IP_ADDRESS vlan=$VLAN_ID acl=${ACL_NUM} rule=$RULE_NUM host=$SWITCH_HOST"
  run_ssh "apply_save" "$CMDS"
  ssh_status=$?
  apply_end=$(date +%s)
  apply_duration=$((apply_end - apply_start))
  log "END action=$ACTION phase=apply_save ip=$IP_ADDRESS status=$ssh_status duration_sec=$apply_duration"

  # Free the rule number allocation after a successful unblock.
  if [ "$ACTION" = "unblock" ] && [ "$ssh_status" = "0" ] \
     && [ -n "${PSQL_BIN:-}" ] && [ -n "${DB_URL:-}" ]; then
    "$PSQL_BIN" "$DB_URL" -c \
      "DELETE FROM acl_rule_allocations WHERE ip_address = '${IP_ADDRESS}';" \
      2>/dev/null || true
  fi

  exit $ssh_status
fi

# Normal invocations should have exited immediately after enqueueing; reaching
# this point without --apply means queue mode was disabled incorrectly.
log "ERROR action=$ACTION ip=$IP_ADDRESS reason=reached_apply_path_without_queue_disable"
exit 1
