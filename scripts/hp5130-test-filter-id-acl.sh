#!/bin/bash
# =============================================================================
# hp5130-test-filter-id-acl.sh — does the HP5130 apply a RADIUS-assigned
# (Filter-Id) authorization ACL to a mac-authenticated wired device, and does
# that ACL filter SAME-VLAN (layer-2) traffic?
#
# Why: SVI packet-filters cannot see traffic between two hosts on the same
# VLAN, and inbound SVI filters are overridden by PBR (see
# hp5130-test-inbound-acl.sh). A per-session ACL assigned by RADIUS is bound
# at the physical port, before any switching/routing decision, so it is the
# one mechanism that can confine an unregistered wired device to the portal.
#
# The three moving parts (all reverted by `remove`):
#   1. switch: create ACL 3002 "PREAUTH-PORT" (DHCP, DNS/HTTP/HTTPS/NTP/ICMP
#      to the Pi, deny everything else). Bound to NOTHING in the config.
#   2. FreeRADIUS: for UNREGISTERED MACs return Filter-Id = "3002" instead of
#      the current inert label "WIRED_UNREGISTERED". Registered devices are
#      untouched.
#   3. switch (automatic): on the device's next mac-auth it binds ACL 3002 to
#      that MAC on its port. This is per-session state — it never appears in
#      `display current-configuration`; see `display mac-authentication
#      connection`.
#
# Usage (on the Pi, as the user owning the switch key and the repo):
#   hp5130-test-filter-id-acl.sh apply  <port-number>      e.g. apply 3
#   hp5130-test-filter-id-acl.sh show   <port-number>
#   hp5130-test-filter-id-acl.sh remove <port-number>
#
# TEST PROTOCOL (device on GigabitEthernet1/0/<port>, unregistered, 10.x.250.y):
#   before:   from device  ping <PI_WIRED_IP e.g. 10.8.250.4>   -> answers
#                          curl -I http://<PI_WIRED_IP>:81          -> answers (NPM admin — the L2 hole)
#                          open the portal                      -> loads
#   apply N
#   unplug / replug the device (or Dashboard -> device -> Disconnect = CoA)
#   show N    -> session on the port should list ACL 3002; FreeRADIUS log
#                should show Filter-Id = "3002" in the Access-Accept
#   from device:           ping <PI_WIRED_IP>      -> NO answer   (same-VLAN traffic dropped at port)
#                          curl -I http://<PI_WIRED_IP>:81 -> fails
#                          ping <PORTAL_IP>        -> answers (permitted)
#                          portal                  -> loads
#   remove N
#
# INTERPRETATION
#   device comes online, ACL listed in session, PI_WIRED_IP unreachable,
#   portal works                 -> Filter-Id ACLs work; implement for real
#   device fails to come online  -> switch could not apply the ACL (check
#                                   `display mac-authentication` and the
#                                   FreeRADIUS log); revert with remove
#   device online, no ACL in session, everything still reachable
#                                -> this release ignores Filter-Id; nothing
#                                   to gain, revert with remove
#
# Environment: SWITCH_HOST (default first of SWITCH_HOSTS), SWITCH_USER,
#   SWITCH_SSH_PORT, SWITCH_KEY_PATH (/keys/... in .env is mapped to ~/.ssh),
#   SWITCH_SSH_KNOWN_HOSTS, SWITCH_SSH_HOSTKEY_POLICY, PORTAL_IP, HIJACK_DNS_IP,
#   WIRED_VLAN, PORTAL_IP_BYTE (all read from .env when unset)
#
# RESULT 2026-11-08, Lei-01, 5130 EI R3507P18: works. Session showed
# "Authorization ACL number/name: 3002"; pings from the device to the Pi's
# wired-VLAN address (same VLAN, L2) stopped while applied and resumed on
# remove; portal kept loading. Deleting the ACL removed filtering from the
# live session WITHOUT a re-auth, so the production ACL must never be
# deleted, only updated in place. This is now the permanent design:
#   - scripts/hp5130-acl-baseline.sh owns ACL 3002 (PREAUTH-PORT)
#   - freeradius/raddb/sites-enabled/default returns Filter-Id "3002" for
#     unregistered/blocked wired MACs and no Filter-Id for registered ones
# With that in place only `show` is useful here; `apply`/`remove` refuse to
# run so they cannot disturb the production ACL.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_DIR/.env}"
RADIUS_SITE="$REPO_DIR/freeradius/raddb/sites-enabled/default"
RADIUS_BAK="$RADIUS_SITE.pre-filter-id-test"
TEST_ACL=3002

envval() {
    [ -f "$ENV_FILE" ] || return 0
    sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'
}

ACTION="${1:-}"
PORT_NUM="${2:-}"

SWITCH_HOST="${SWITCH_HOST:-$(envval SWITCH_HOSTS | awk '{print $1}')}"
SWITCH_USER="${SWITCH_USER:-$(envval SWITCH_USER)}"; SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
if [ -z "${SWITCH_KEY_PATH:-}" ]; then
    _k="$(envval SWITCH_KEY_PATH)"
    case "$_k" in
        /keys/*) SWITCH_KEY_PATH="$HOME/.ssh/${_k#/keys/}" ;;
        ?*)      SWITCH_KEY_PATH="$_k" ;;
        *)       SWITCH_KEY_PATH="$HOME/.ssh/id_rsa" ;;
    esac
fi
[ -r "$SWITCH_KEY_PATH" ] || { echo "switch SSH key not readable: $SWITCH_KEY_PATH" >&2; exit 1; }
SWITCH_SSH_KNOWN_HOSTS="${SWITCH_SSH_KNOWN_HOSTS:-$REPO_DIR/shared/ssh-known-hosts/known_hosts}"
[ -r "$SWITCH_SSH_KNOWN_HOSTS" ] || SWITCH_SSH_KNOWN_HOSTS="$HOME/.ssh/known_hosts"
SWITCH_SSH_HOSTKEY_POLICY="${SWITCH_SSH_HOSTKEY_POLICY:-accept-new}"

PORTAL_IP="${PORTAL_IP:-$(envval PORTAL_IP)}"
HIJACK_DNS_IP="${HIJACK_DNS_IP:-$(envval HIJACK_DNS_IP)}"
WIRED_VLAN="${WIRED_VLAN:-$(envval WIRED_VLAN)}"; WIRED_VLAN="${WIRED_VLAN:-250}"
NETWORK_WORD="${NETWORK_WORD:-$(envval NETWORK_WORD)}"
PORTAL_IP_BYTE="${PORTAL_IP_BYTE:-$(envval PORTAL_IP_BYTE)}"; PORTAL_IP_BYTE="${PORTAL_IP_BYTE:-4}"
PI_WIRED_IP="${NETWORK_WORD}.${WIRED_VLAN}.${PORTAL_IP_BYTE}"
[ -n "$PORTAL_IP" ] && [ -n "$HIJACK_DNS_IP" ] || { echo "PORTAL_IP / HIJACK_DNS_IP not found in $ENV_FILE" >&2; exit 1; }

SSH_OPTS=(-tt -i "$SWITCH_KEY_PATH" -p "$SWITCH_SSH_PORT"
          -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa
          -o StrictHostKeyChecking="$SWITCH_SSH_HOSTKEY_POLICY"
          -o UserKnownHostsFile="$SWITCH_SSH_KNOWN_HOSTS"
          -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)

usage() { sed -n '2,/^# ====/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; exit 1; }
case "$PORT_NUM" in ''|*[!0-9]*) usage ;; esac
IFACE="GigabitEthernet1/0/${PORT_NUM}"

run_switch() {
    local out; out="$(mktemp)"
    { printf 'screen-length disable\n'; cat; printf 'quit\n'; } \
        | timeout 60 ssh "${SSH_OPTS[@]}" "${SWITCH_USER}@${SWITCH_HOST}" >"$out" 2>&1 || true
    tr -d '\r' <"$out" | grep -vE '^\s*$|post-quantum|store now|openssh.com/pq' || true
    rm -f "$out"
}
switch_errors() {
    grep -qE "% (Wrong parameter|Incomplete command|Too many parameters|Unrecognized command)|Error:|Failed to|Not enough" <<<"$1"
}

restart_radius() {
    echo "--- restarting freeradius"
    (cd "$REPO_DIR" && docker compose restart freeradius >/dev/null 2>&1)
    for _ in $(seq 1 20); do
        if docker logs freeradius --since 30s 2>&1 | grep -q "Ready to process requests"; then
            echo "--- freeradius ready"; return 0
        fi
        if docker logs freeradius --since 30s 2>&1 | grep -q "FATAL"; then
            echo "!!! freeradius failed to start:" >&2
            docker logs freeradius --since 30s 2>&1 | grep -A5 FATAL >&2
            return 1
        fi
        sleep 1
    done
    echo "!!! freeradius did not report ready; check: docker logs freeradius" >&2
    return 1
}

do_apply() {
    if grep -q "Filter-Id := \"$TEST_ACL\"" "$RADIUS_SITE" && [ ! -f "$RADIUS_BAK" ]; then
        echo "Filter-Id $TEST_ACL is now the permanent FreeRADIUS config and the baseline owns ACL $TEST_ACL." >&2
        echo "Nothing to apply — use: $0 show <port>" >&2
        exit 0
    fi
    if [ -f "$RADIUS_BAK" ]; then
        echo "!!! $RADIUS_BAK exists — a previous test was not removed. Run: $0 remove $PORT_NUM" >&2
        exit 1
    fi
    if ! grep -q 'Filter-Id := "WIRED_UNREGISTERED"' "$RADIUS_SITE"; then
        echo "!!! expected 'Filter-Id := \"WIRED_UNREGISTERED\"' in $RADIUS_SITE — layout changed, aborting" >&2
        exit 1
    fi

    echo "--- step 1/3: creating ACL $TEST_ACL on $SWITCH_HOST (bound to nothing)"
    out="$(run_switch <<EOF
system-view
undo acl advanced $TEST_ACL
acl advanced $TEST_ACL
 description PREAUTH-PORT RADIUS-Filter-Id test - remove me
 rule 1 permit udp source-port eq bootpc destination-port eq bootps
 rule 5 permit udp destination $PORTAL_IP 0 destination-port eq dns
 rule 6 permit tcp destination $PORTAL_IP 0 destination-port eq dns
 rule 7 permit udp destination $HIJACK_DNS_IP 0 destination-port eq dns
 rule 8 permit tcp destination $HIJACK_DNS_IP 0 destination-port eq dns
 rule 10 permit tcp destination $PORTAL_IP 0 destination-port eq www
 rule 11 permit tcp destination $PORTAL_IP 0 destination-port eq 443
 rule 13 permit tcp destination $HIJACK_DNS_IP 0 destination-port eq 443
 rule 14 permit udp destination $PORTAL_IP 0 destination-port eq ntp
 rule 15 permit icmp destination $PORTAL_IP 0
 rule 100 deny ip counting
quit
quit
EOF
)"
    printf '%s\n' "$out" | grep -vE '^(<|\[)' || true
    if switch_errors "$out"; then
        echo "!!! switch rejected the ACL; nothing else changed" >&2
        exit 1
    fi

    echo "--- step 2/3: FreeRADIUS unregistered branch -> Filter-Id \"$TEST_ACL\" (backup: $RADIUS_BAK)"
    cp -p "$RADIUS_SITE" "$RADIUS_BAK"
    sed -i "s/Filter-Id := \"WIRED_UNREGISTERED\"/Filter-Id := \"$TEST_ACL\"/" "$RADIUS_SITE"
    grep -n "Filter-Id :=" "$RADIUS_SITE"
    if ! restart_radius; then
        echo "--- reverting FreeRADIUS change" >&2
        mv -f "$RADIUS_BAK" "$RADIUS_SITE"
        restart_radius || true
        exit 1
    fi

    cat <<EOF

--- step 3/3 is the switch's job. Now:
    1. Unplug and replug the device on $IFACE (or Dashboard -> device -> Disconnect).
    2. $0 show $PORT_NUM
         -> look for ACL $TEST_ACL in the mac-authentication session, and
            Filter-Id = "$TEST_ACL" in the FreeRADIUS Access-Accept.
    3. From the device:
         ping $PI_WIRED_IP        # same VLAN, L2  -> should now FAIL
         curl -I http://$PI_WIRED_IP:81   # NPM admin     -> should now FAIL
         ping $PORTAL_IP        # permitted      -> should answer
         open the portal page   # should load
    4. $0 remove $PORT_NUM
EOF
}

do_show() {
    echo "=== switch: mac-auth session(s) on $IFACE ==="
    run_switch <<EOF | grep -vE '^(<|\[)' || true
display mac-authentication connection interface $IFACE
display mac-authentication interface $IFACE
display acl $TEST_ACL
EOF
    echo
    echo "=== FreeRADIUS: last Access-Accept(s) ==="
    docker logs freeradius 2>&1 | grep -E "Sent Access-Accept|Filter-Id|Tunnel-Private-Group-Id|Login OK|Login incorrect" | tail -8
}

do_remove() {
    if grep -q "Filter-Id := \"$TEST_ACL\"" "$RADIUS_SITE" && [ ! -f "$RADIUS_BAK" ]; then
        echo "Refusing: ACL $TEST_ACL is the production PREAUTH-PORT ACL (FreeRADIUS returns it permanently)." >&2
        echo "Deleting it would silently unfilter every online unregistered wired device." >&2
        echo "It is maintained by scripts/hp5130-acl-baseline.sh." >&2
        exit 1
    fi
    if [ -f "$RADIUS_BAK" ]; then
        echo "--- restoring FreeRADIUS config from $RADIUS_BAK"
        mv -f "$RADIUS_BAK" "$RADIUS_SITE"
        restart_radius || true
    else
        echo "--- no FreeRADIUS backup found (already restored?)"
    fi
    echo "--- removing ACL $TEST_ACL from the switch (any session still using it will re-authenticate)"
    run_switch <<EOF | grep -vE '^(<|\[)' || true
system-view
undo acl advanced $TEST_ACL
quit
EOF
    echo "--- done. Replug the test device so it comes back without the ACL."
}

case "$ACTION" in
    apply)  do_apply ;;
    show)   do_show ;;
    remove) do_remove ;;
    *)      usage ;;
esac
