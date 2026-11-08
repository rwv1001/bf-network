#!/bin/bash
# =============================================================================
# hp5130-test-inbound-acl.sh — does an INBOUND SVI packet-filter take effect
# on a VLAN interface that also has PBR applied?
#
# Background: per-device blocks are written OUTBOUND on the ISP uplink SVIs
# because an earlier inbound design was dropped with the note "conflicts with
# PBR" and no detail. This script lets you find out empirically, on one
# device, with automatic rollback.
#
# It creates a throwaway ACL 3<vlan>0 (e.g. 3210 for VLAN 21):
#     rule 10    deny   ip source <test-ip> 0   counting
#     rule 30000 permit ip                      counting
# and binds it  packet-filter 3<vlan>0 inbound  on Vlan-interface<vlan>,
# leaving the existing outbound filter and PBR untouched.
#
# Usage (run on the Pi, as the user that owns the switch SSH key):
#   hp5130-test-inbound-acl.sh apply  <vlan> <test-ip> [revert-seconds]
#   hp5130-test-inbound-acl.sh show   <vlan>
#   hp5130-test-inbound-acl.sh remove <vlan>
#
# apply schedules an automatic remove after revert-seconds (default 600) via
# a detached background job, so losing your SSH session cannot leave the
# test ACL behind. Run remove yourself as soon as you have the result.
#
# TEST PROTOCOL (test-ip = device A, other-ip = device B, both on the VLAN):
#   Before apply, from A:   ping 8.8.8.8     ping <PORTAL_IP>     ping <B>
#   apply, then from A:     ping 8.8.8.8     ping <PORTAL_IP>     ping <B>
#   show                    -> rule 10 "times matched" counter
#   remove
#
# INTERPRETATION
#   8.8.8.8 fails       inbound deny is honoured ON THE PBR PATH (node 10)
#   PORTAL_IP fails     inbound deny is honoured on the normally-routed path
#                       (PBR node 5 deny -> FIB); this is the control case
#   B still answers     expected: same-VLAN traffic is L2-switched and never
#                       crosses the SVI, so no SVI ACL can stop it
#   8.8.8.8 works but PORTAL_IP fails
#                       PBR is applied BEFORE / overrides the inbound filter
#                       on this firmware -> inbound blocking is NOT reliable
#   rule 10 counter 0 while A was pinging
#                       the filter was never consulted for A's traffic
#   "Failed to apply or refresh ACL" / "Not enough resources" in the output
#                       TCAM exhaustion: inbound filter + PBR on one SVI does
#                       not fit — the likely original "conflict"
#
# Environment (same conventions as the other hp5130-*.sh scripts):
#   SWITCH_HOST (default: first of SWITCH_HOSTS in .env), SWITCH_USER,
#   SWITCH_SSH_PORT, SWITCH_KEY_PATH (default ~/.ssh/id_rsa),
#   SWITCH_SSH_KNOWN_HOSTS, SWITCH_SSH_HOSTKEY_POLICY
#
# RESULT 2026-11-08, Lei-01, HPE 5130 EI, Comware 7.1.070 R3507P18:
#   apply 21 10.8.21.7 with PBR-BT bound to Vlan-interface21. Both filters
#   bound without error. Rule 10 counted 243 packets, yet continuous pings
#   from 10.8.21.7 to 8.8.8.8 (PBR node 10), 10.8.99.4 (PBR deny node 5 ->
#   normal routing) and 10.8.21.6 (L2) all kept answering. Conclusion: on a
#   PBR-bound SVI the inbound packet-filter deny is overridden by the PBR
#   action. Per-device blocks must stay OUTBOUND on the uplink SVIs.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_DIR/.env}"

envval() {
    [ -f "$ENV_FILE" ] || return 0
    sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'
}

ACTION="${1:-}"
VLAN="${2:-}"
TEST_IP="${3:-}"
REVERT_SEC="${4:-600}"

SWITCH_HOST="${SWITCH_HOST:-$(envval SWITCH_HOSTS | awk '{print $1}')}"
SWITCH_USER="${SWITCH_USER:-$(envval SWITCH_USER)}"; SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
# .env holds the container path (/keys/<name>); containers mount ~/.ssh at /keys.
if [ -z "${SWITCH_KEY_PATH:-}" ]; then
    _env_key="$(envval SWITCH_KEY_PATH)"
    case "$_env_key" in
        /keys/*) SWITCH_KEY_PATH="$HOME/.ssh/${_env_key#/keys/}" ;;
        ?*)      SWITCH_KEY_PATH="$_env_key" ;;
        *)       SWITCH_KEY_PATH="$HOME/.ssh/id_rsa" ;;
    esac
fi
[ -r "$SWITCH_KEY_PATH" ] || { echo "switch SSH key not readable: $SWITCH_KEY_PATH (set SWITCH_KEY_PATH)" >&2; exit 1; }
SWITCH_SSH_KNOWN_HOSTS="${SWITCH_SSH_KNOWN_HOSTS:-$REPO_DIR/shared/ssh-known-hosts/known_hosts}"
[ -r "$SWITCH_SSH_KNOWN_HOSTS" ] || SWITCH_SSH_KNOWN_HOSTS="$HOME/.ssh/known_hosts"
SWITCH_SSH_HOSTKEY_POLICY="${SWITCH_SSH_HOSTKEY_POLICY:-accept-new}"

SSH_OPTS=(-tt -i "$SWITCH_KEY_PATH" -p "$SWITCH_SSH_PORT"
          -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa
          -o StrictHostKeyChecking="$SWITCH_SSH_HOSTKEY_POLICY"
          -o UserKnownHostsFile="$SWITCH_SSH_KNOWN_HOSTS"
          -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)

usage() {
    sed -n '2,/^# ====/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
    exit 1
}

case "$VLAN" in ''|*[!0-9]*) usage ;; esac
if [ "$VLAN" -lt 1 ] || [ "$VLAN" -gt 99 ]; then
    echo "VLAN must be 1-99 so the test ACL 3${VLAN}0 stays in the advanced range" >&2
    exit 1
fi
ACL="3${VLAN}0"
IFACE="Vlan-interface${VLAN}"
STATE="/tmp/hp5130-test-inbound-acl.${SWITCH_HOST}.vlan${VLAN}"

run_switch() {
    # stdin: command lines (already inside user view). Echoes switch output.
    local out
    out="$(mktemp)"
    { printf 'screen-length disable\n'; cat; printf 'quit\n'; } \
        | timeout 60 ssh "${SSH_OPTS[@]}" "${SWITCH_USER}@${SWITCH_HOST}" >"$out" 2>&1 || true
    # Strip terminal noise and echo back
    tr -d '\r' <"$out" | grep -v '^\s*$' || true
    rm -f "$out"
}

check_errors() {
    if grep -qE "% (Wrong parameter|Incomplete command|Too many parameters|Unrecognized command)|Error:|Failed to|Not enough|resource" <<<"$1"; then
        echo
        echo "!!! The switch reported a problem (see above). Nothing else was changed." >&2
        return 1
    fi
    return 0
}

do_remove() {
    echo "--- removing test ACL $ACL from $IFACE on $SWITCH_HOST"
    out="$(run_switch <<EOF
system-view
interface $IFACE
undo packet-filter $ACL inbound
quit
undo acl advanced $ACL
quit
EOF
)"
    printf '%s\n' "$out" | grep -vE '^(<|\[)' || true
    rm -f "$STATE"
    echo "--- done. Confirm with: $SELF show $VLAN"
}

do_show() {
    # display acl often shows no hit counts for hardware packet filters;
    # display packet-filter statistics is the authoritative counter.
    run_switch <<EOF
display acl $ACL
display packet-filter statistics interface $IFACE inbound
display packet-filter interface $IFACE
display current-configuration interface $IFACE
EOF
}

do_apply() {
    case "$TEST_IP" in
        *.*.*.*) ;;
        *) echo "test-ip required (IPv4 of the device to block)" >&2; exit 1 ;;
    esac
    echo "--- current state of $IFACE (before):"
    run_switch <<EOF | grep -E "packet-filter|policy-based-route|ip address|Vlan-interface" || true
display current-configuration interface $IFACE
EOF
    echo
    echo "--- applying test ACL $ACL inbound on $IFACE: deny $TEST_IP, permit everything else"
    out="$(run_switch <<EOF
system-view
undo acl advanced $ACL
acl advanced $ACL
 description TEST-inbound-vs-PBR-remove-me
 rule 10 deny ip source $TEST_IP 0 counting
 rule 30000 permit ip counting
quit
interface $IFACE
 packet-filter $ACL inbound
quit
quit
EOF
)"
    printf '%s\n' "$out" | grep -vE '^(<|\[)' || true
    if ! check_errors "$out"; then
        do_remove
        exit 1
    fi
    date +%s >"$STATE"

    # Detached auto-revert so a dropped SSH session cannot leave the ACL behind.
    if [ "$REVERT_SEC" -gt 0 ] 2>/dev/null; then
        setsid nohup bash -c "sleep $REVERT_SEC; [ -f '$STATE' ] && '$SELF' remove '$VLAN'" \
            >"/tmp/hp5130-test-inbound-acl.revert.log" 2>&1 < /dev/null &
        echo "--- auto-revert scheduled in ${REVERT_SEC}s (log: /tmp/hp5130-test-inbound-acl.revert.log)"
    fi

    cat <<EOF

--- APPLIED. Now, from the device $TEST_IP, run:
      ping -c 4 8.8.8.8          # internet  -> PBR node 10 path
      ping -c 4 $(envval PORTAL_IP)          # portal    -> PBR node 5 deny, normal routing
      ping -c 4 <other device on VLAN $VLAN>   # same VLAN -> L2, should still work
    then:
      $SELF show $VLAN      # look at "times matched" on rule 10 / rule 30000
      $SELF remove $VLAN    # as soon as you have the answer

    Read the INTERPRETATION block at the top of this script.
EOF
}

case "$ACTION" in
    apply)  do_apply ;;
    show)   do_show ;;
    remove) do_remove ;;
    *)      usage ;;
esac
