#!/bin/bash
# =============================================================================
# pi-host-firewall.sh — host INPUT allow-list for traffic from user VLANs
#
# Why: the Pi has an address on every user VLAN (enp1s0.<vlan> = 10.x.<vlan>.4)
# so a device on a user VLAN reaches the Pi at L2, bypassing every switch ACL.
# The switch also permits user VLANs to reach PORTAL_IP/HIJACK_DNS_IP on any
# port. Either way an unregistered device could reach NPM admin (81), Pi-hole
# (8055), UniFi (8080/8443/...), SSH, syslog, TFTP. This script lets traffic
# *sourced from user-VLAN subnets* reach only what the captive portal needs.
#
# What is NOT restricted (default ACCEPT policy is kept):
#   - loopback (the Oracle VPS reverse tunnels — including the VS Code SSH
#     session — arrive on 127.0.0.1)
#   - established/related connections (outbound tunnels, replies)
#   - management VLAN, Wi-Fi/ISP LAN, VPS, routers — any non-user-VLAN source
#
# Usage (root, or a user with passwordless sudo for iptables; plan needs neither):
#   pi-host-firewall.sh apply     install/refresh rules (idempotent)
#   pi-host-firewall.sh remove    remove all rules added by this script
#   pi-host-firewall.sh status    show the chains
#   pi-host-firewall.sh plan      print the interfaces/subnets/ports it would use
#
# Reads .env from $ENV_FILE (default: <repo>/.env). Relevant keys:
#   NETWORK_WORD, VLAN_PREFIX_MAP, VALID_VLANS, WIRED_VLAN, MANAGEMENT_VLAN,
#   WAN_IFACE, PREAUTH_PROXY_PORT, PI_FW_ALLOW_SSH_FROM_USER_VLANS (0/1),
#   PI_FW_EXTRA_TCP_PORTS, PI_FW_EXTRA_UDP_PORTS (comma lists, optional)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_DIR/.env}"
ACTION="${1:-apply}"

CHAIN_IN="BF-INPUT"
CHAIN_USER="BF-USER-VLAN"

log() { printf '%s pi-host-firewall: %s\n' "$(date -Iseconds)" "$*" >&2; }

# Root directly, or an unprivileged user with passwordless sudo for iptables
# (the captive-portal-web container runs this at start-up as the portal user).
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if [ "$ACTION" = "plan" ]; then
        :
    elif sudo -n iptables -S INPUT >/dev/null 2>&1; then
        SUDO="sudo -n"
    else
        echo "pi-host-firewall: must run as root (or with passwordless sudo for iptables)" >&2
        exit 1
    fi
fi
ipt4() { $SUDO iptables "$@"; }
ipt6() { $SUDO ip6tables "$@"; }

# ── Load the few .env keys we need (never source: .env is compose syntax) ───
envval() {
    # $1 key → value with surrounding single/double quotes stripped; empty if unset.
    [ -f "$ENV_FILE" ] || return 0
    sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'
}
[ -f "$ENV_FILE" ] || log "WARNING: $ENV_FILE not found; relying on environment"

NETWORK_WORD="${NETWORK_WORD:-$(envval NETWORK_WORD)}"
VLAN_PREFIX_MAP="${VLAN_PREFIX_MAP:-$(envval VLAN_PREFIX_MAP)}"
VALID_VLANS="${VALID_VLANS:-$(envval VALID_VLANS)}"
WIRED_VLAN="${WIRED_VLAN:-$(envval WIRED_VLAN)}"; WIRED_VLAN="${WIRED_VLAN:-250}"
MANAGEMENT_VLAN="${MANAGEMENT_VLAN:-$(envval MANAGEMENT_VLAN)}"; MANAGEMENT_VLAN="${MANAGEMENT_VLAN:-99}"
WAN_IFACE="${WAN_IFACE:-$(envval WAN_IFACE)}"; WAN_IFACE="${WAN_IFACE:-eth0}"
PREAUTH_PROXY_PORT="${PREAUTH_PROXY_PORT:-$(envval PREAUTH_PROXY_PORT)}"; PREAUTH_PROXY_PORT="${PREAUTH_PROXY_PORT:-8443}"
ALLOW_SSH="${PI_FW_ALLOW_SSH_FROM_USER_VLANS:-$(envval PI_FW_ALLOW_SSH_FROM_USER_VLANS)}"; ALLOW_SSH="${ALLOW_SSH:-0}"
EXTRA_TCP="${PI_FW_EXTRA_TCP_PORTS:-$(envval PI_FW_EXTRA_TCP_PORTS)}"
EXTRA_UDP="${PI_FW_EXTRA_UDP_PORTS:-$(envval PI_FW_EXTRA_UDP_PORTS)}"

HAVE_IPT="$(command -v iptables || true)"
[ -n "$HAVE_IPT" ] || [ "$ACTION" = "plan" ] || { echo "iptables not found" >&2; exit 1; }
# ip6tables is optional (may be absent, or not permitted via sudo).
HAVE_IP6T=0
if command -v ip6tables >/dev/null 2>&1 && [ "$ACTION" != "plan" ] && ipt6 -S INPUT >/dev/null 2>&1; then
    HAVE_IP6T=1
fi

# ── Work out the user-VLAN subnets and interfaces ────────────────────────────
# VLAN_PREFIX_MAP, when set, is authoritative ("11:10.8.11,21:10.8.21,...").
# Otherwise fall back to NETWORK_WORD.<vlan>.0/24.
user_vlans() {
    printf '%s,%s' "$VALID_VLANS" "$WIRED_VLAN" | tr ',; ' '\n\n\n' | grep -E '^[0-9]+$' \
        | grep -vx "$MANAGEMENT_VLAN" | sort -un
}

subnet_for_vlan() {
    local vlan="$1" entry prefix
    if [ -n "${VLAN_PREFIX_MAP:-}" ]; then
        for entry in $(printf '%s' "$VLAN_PREFIX_MAP" | tr ',; ' '\n\n\n'); do
            case "$entry" in
                "$vlan":*)
                    prefix="${entry#*:}"
                    case "$prefix" in
                        */*) printf '%s\n' "$prefix"; return 0 ;;
                        *.*.*.*) printf '%s/32\n' "$prefix"; return 0 ;;
                        *.*.*) printf '%s.0/24\n' "$prefix"; return 0 ;;
                        *.*) printf '%s.0.0/16\n' "$prefix"; return 0 ;;
                    esac
                    ;;
            esac
        done
    fi
    if [ -n "$NETWORK_WORD" ]; then
        case "$NETWORK_WORD" in
            *.*.*) printf '%s.0/24\n' "$NETWORK_WORD" ;;      # already /24 word
            *.*)   printf '%s.%s.0/24\n' "$NETWORK_WORD" "$vlan" ;;
        esac
        return 0
    fi
    return 1
}

VLANS="$(user_vlans)"
if [ -z "$VLANS" ]; then
    log "no user VLANs resolved from VALID_VLANS/WIRED_VLAN — nothing to do"
    exit 0
fi

# ── Helpers ──────────────────────────────────────────────────────────────────
ensure_chain() { "$1" -N "$2" 2>/dev/null || "$1" -F "$2"; }
ensure_jump_first() {
    # Exactly one jump to $3, as the first rule of $2.
    local ipt="$1" parent="$2" target="$3"
    while "$ipt" -C "$parent" -j "$target" 2>/dev/null; do "$ipt" -D "$parent" -j "$target"; done
    "$ipt" -I "$parent" 1 -j "$target"
}
remove_chain() {
    local ipt="$1" parent="$2" chain="$3"
    while "$ipt" -C "$parent" -j "$chain" 2>/dev/null; do "$ipt" -D "$parent" -j "$chain"; done
    "$ipt" -F "$chain" 2>/dev/null || true
    "$ipt" -X "$chain" 2>/dev/null || true
}

apply_v4() {
    ensure_chain ipt4 "$CHAIN_IN"
    ensure_chain ipt4 "$CHAIN_USER"

    # --- BF-INPUT: decide who is subject to the allow-list -------------------
    ipt4 -A "$CHAIN_IN" -i lo -j RETURN
    ipt4 -A "$CHAIN_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for vlan in $VLANS; do
        iface="${WAN_IFACE}.${vlan}"
        # DHCP DISCOVER arrives with source 0.0.0.0, so match it by interface.
        ipt4 -A "$CHAIN_IN" -i "$iface" -p udp --dport 67 -j RETURN
        # mDNS / discovery reflector listens for multicast & broadcast here.
        ipt4 -A "$CHAIN_IN" -i "$iface" -m addrtype --dst-type MULTICAST -j RETURN
        ipt4 -A "$CHAIN_IN" -i "$iface" -m addrtype --dst-type BROADCAST -j RETURN
        # Anything else that physically arrives on a user VLAN is user traffic
        # regardless of claimed source.
        ipt4 -A "$CHAIN_IN" -i "$iface" -j "$CHAIN_USER"
        subnet="$(subnet_for_vlan "$vlan" || true)"
        if [ -n "$subnet" ]; then
            # Same subnets arriving via the switch on the mgmt VLAN / macvlan.
            ipt4 -A "$CHAIN_IN" -s "$subnet" -j "$CHAIN_USER"
            log "user VLAN $vlan: iface=$iface subnet=$subnet"
        else
            log "user VLAN $vlan: iface=$iface (no subnet resolved)"
        fi
    done

    # --- BF-USER-VLAN: what an unregistered/any user device may reach --------
    ipt4 -A "$CHAIN_USER" -p icmp -j RETURN
    ipt4 -A "$CHAIN_USER" -p udp --dport 67 -j RETURN                       # DHCP unicast renew
    ipt4 -A "$CHAIN_USER" -p udp --dport 53 -j RETURN                       # Pi-hole / hijack DNS
    ipt4 -A "$CHAIN_USER" -p tcp --dport 53 -j RETURN
    ipt4 -A "$CHAIN_USER" -p tcp --dport 80 -j RETURN                       # portal via NPM
    ipt4 -A "$CHAIN_USER" -p tcp --dport 443 -j RETURN
    ipt4 -A "$CHAIN_USER" -p tcp --dport "$PREAUTH_PROXY_PORT" -j RETURN    # post-REDIRECT of HIJACK_IP:443
    ipt4 -A "$CHAIN_USER" -p udp --dport 123 -j RETURN                      # NTP
    if [ "$ALLOW_SSH" = "1" ]; then
        ipt4 -A "$CHAIN_USER" -p tcp --dport 22 -j RETURN
    fi
    for p in $(printf '%s' "$EXTRA_TCP" | tr ',; ' '\n\n\n' | grep -E '^[0-9]+$'); do
        ipt4 -A "$CHAIN_USER" -p tcp --dport "$p" -j RETURN
    done
    for p in $(printf '%s' "$EXTRA_UDP" | tr ',; ' '\n\n\n' | grep -E '^[0-9]+$'); do
        ipt4 -A "$CHAIN_USER" -p udp --dport "$p" -j RETURN
    done
    ipt4 -A "$CHAIN_USER" -j DROP

    ensure_jump_first ipt4 INPUT "$CHAIN_IN"
}

apply_v6() {
    if [ "$HAVE_IP6T" != 1 ]; then
        log "ip6tables unavailable or not permitted; skipping IPv6 rules"
        return 0
    fi
    # The Pi only serves IPv4 to clients; on user-VLAN interfaces keep
    # neighbour discovery and multicast, drop the rest. Non-user interfaces
    # and loopback untouched.
    ensure_chain ipt6 "$CHAIN_IN"
    ipt6 -A "$CHAIN_IN" -i lo -j RETURN
    ipt6 -A "$CHAIN_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for vlan in $VLANS; do
        iface="${WAN_IFACE}.${vlan}"
        ipt6 -A "$CHAIN_IN" -i "$iface" -p ipv6-icmp -j RETURN
        ipt6 -A "$CHAIN_IN" -i "$iface" -m addrtype --dst-type MULTICAST -j RETURN
        ipt6 -A "$CHAIN_IN" -i "$iface" -j DROP
    done
    ensure_jump_first ipt6 INPUT "$CHAIN_IN"
}

case "$ACTION" in
    apply)
        apply_v4
        apply_v6
        log "applied (ssh from user VLANs: $([ "$ALLOW_SSH" = 1 ] && echo allowed || echo blocked))"
        ;;
    remove)
        remove_chain ipt4 INPUT "$CHAIN_IN"
        ipt4 -F "$CHAIN_USER" 2>/dev/null || true
        ipt4 -X "$CHAIN_USER" 2>/dev/null || true
        [ "$HAVE_IP6T" = 1 ] && remove_chain ipt6 INPUT "$CHAIN_IN"
        log "removed"
        ;;
    status)
        ipt4 -S INPUT | head -3
        ipt4 -S "$CHAIN_IN" 2>/dev/null || echo "($CHAIN_IN not installed)"
        echo "--- $CHAIN_USER (packet counters) ---"
        ipt4 -L "$CHAIN_USER" -n -v 2>/dev/null || true
        ;;
    plan)
        echo "env file:        $ENV_FILE"
        echo "restricted VLANs:"
        for vlan in $VLANS; do
            printf '  vlan %-4s iface %-14s subnet %s\n' "$vlan" "${WAN_IFACE}.${vlan}" "$(subnet_for_vlan "$vlan" || echo '(none)')"
        done
        echo "allowed from them: icmp, udp 67, udp/tcp 53, tcp 80, tcp 443, tcp $PREAUTH_PROXY_PORT, udp 123"
        [ "$ALLOW_SSH" = 1 ] && echo "                   tcp 22 (PI_FW_ALLOW_SSH_FROM_USER_VLANS=1)"
        [ -n "$EXTRA_TCP" ] && echo "                   extra tcp: $EXTRA_TCP"
        [ -n "$EXTRA_UDP" ] && echo "                   extra udp: $EXTRA_UDP"
        echo "unrestricted:      lo, established/related, ${WAN_IFACE}.${MANAGEMENT_VLAN}, Wi-Fi/ISP/VPS and all other sources"
        ;;
    *)
        echo "Usage: $0 {apply|remove|status}" >&2
        exit 1
        ;;
esac
