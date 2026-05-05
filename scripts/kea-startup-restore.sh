#!/bin/sh
# kea-startup-restore.sh — Restore DNS hijack iptables rules on Kea startup.
#
# Called from the Kea container entrypoint before kea-dhcp4 starts.
# Ensures:
#   1. Blocked-pool range DNAT rules are present (defence against host reboots /
#      iptables flushes that bypass reset_dns_hijack_rules()).
#   2. Per-IP DNAT rules are restored for all pending (unregistered) main-pool
#      devices recorded in the captive-portal DB — so devices that hold a cached
#      DHCP lease and never re-DISCOVER after a Kea restart are still hijacked.
#   3. HP5130 switch ACL blocks are re-applied in the background for the same
#      devices (idempotent — the switch ignores duplicate rules).
#
# Exits 0 on success or non-fatal errors.  Never exits non-zero (called with
# "|| true" in the entrypoint so Kea always starts regardless).

DNS_SCRIPT="/scripts/dns-hijack.sh"
ACL_SCRIPT="/scripts/hp5130-acl.sh"

log() {
    echo "$(date -Iseconds) kea-startup-restore: $1" >&2
}

# ── Step 1: Blocked-pool range DNAT rules (always, idempotent) ───────────────

if [ ! -x "$DNS_SCRIPT" ]; then
    log "ERROR: $DNS_SCRIPT not found or not executable — aborting"
    exit 0
fi

log "Restoring blocked-pool DNS hijack ranges..."
if "$DNS_SCRIPT" hijack-blocked-pools 2>&1 | while IFS= read -r line; do log "  [hijack-blocked-pools] $line"; done; then
    log "Blocked-pool ranges restored OK"
else
    log "WARNING: blocked-pool range restore exited non-zero (iptables may be unavailable yet)"
fi

# ── Step 2: Per-IP DNAT rules for pending (unregistered) main-pool devices ───

if [ -z "${DB_HOST:-}" ] || [ -z "${DB_USER:-}" ] || [ -z "${DB_PASSWORD:-}" ] || [ -z "${DB_NAME:-}" ]; then
    log "DB credentials not set — skipping per-IP hijack restore"
    exit 0
fi

log "Querying pending devices for per-IP DNS hijack restore..."

# Select IPs of pending devices whose lease is NOT from the blocked pool.
# If ip_leases has from_blocked_pool=true for this IP, the range rules cover it.
# If ip_leases has no record (e.g. after reset_test_data cleared it), we still
# attempt to restore the rule — dns-hijack.sh hijack is idempotent.
IPS=$(PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$DB_NAME" \
    --tuples-only --no-align \
    --command="
        SELECT d.ip_address
        FROM devices d
        WHERE d.registration_status NOT IN ('registered', 'approved')
          AND d.ip_address IS NOT NULL
          AND d.ip_address <> ''
          AND NOT EXISTS (
              SELECT 1 FROM ip_leases l
              WHERE l.ip_address = d.ip_address
                AND l.from_blocked_pool = true
          )
        ORDER BY d.ip_address
    " 2>/dev/null) || true

# Strip any stray whitespace / blank lines
IPS=$(printf '%s\n' "$IPS" | grep -E '^[0-9]+\.' || true)

if [ -z "$IPS" ]; then
    log "No pending main-pool devices found — per-IP restore not needed"
    exit 0
fi

n_total=$(printf '%s\n' "$IPS" | wc -l | tr -d ' ')
log "Restoring per-IP DNS hijack for $n_total device(s)..."

n_ok=0
n_fail=0

for ip in $IPS; do
    if "$DNS_SCRIPT" hijack "$ip" 2>/dev/null; then
        log "  hijack OK: $ip"
        n_ok=$((n_ok + 1))
    else
        log "  WARNING: hijack FAILED: $ip"
        n_fail=$((n_fail + 1))
    fi
done

log "Per-IP DNS hijack restore done: $n_ok OK, $n_fail failed"

# ── Step 3: Switch ACL blocks (background, non-critical) ─────────────────────
# The switch may already have these rules (they survive Kea restarts).
# Re-applying is safe because hp5130-acl.sh checks before adding (idempotent).

if [ ! -x "$ACL_SCRIPT" ]; then
    log "ACL script not found — skipping switch ACL restore"
    exit 0
fi

if [ -z "${SWITCH_HOSTS:-}" ]; then
    log "SWITCH_HOSTS not set — skipping switch ACL restore"
    exit 0
fi

(
    n_acl_ok=0
    n_acl_fail=0
    for ip in $IPS; do
        for sw in $SWITCH_HOSTS; do
            if SWITCH_HOSTS="$sw" ACL_QUEUE_DISABLE=1 "$ACL_SCRIPT" block "$ip" 2>/dev/null; then
                log "  ACL block OK: $ip via $sw"
                n_acl_ok=$((n_acl_ok + 1))
            else
                log "  WARNING: ACL block FAILED: $ip via $sw"
                n_acl_fail=$((n_acl_fail + 1))
            fi
        done
    done
    log "Switch ACL restore done: $n_acl_ok OK, $n_acl_fail failed"
) &

log "Switch ACL restore started in background (PID $!)"
