#!/bin/sh
# DNS Hijacking Management Script
# Redirects DNS requests from unregistered devices to hijacking DNSmasq

ACTION="$1"
IP_ADDRESS="$2"

# Required environment variables – fail loudly if not set
PORTAL_IP="${PORTAL_IP:?PORTAL_IP environment variable is required (Pi VLAN-99 IP, e.g. 192.168.99.4)}"
HIJACK_DNS_IP="${HIJACK_DNS_IP:?HIJACK_DNS_IP environment variable is required (dnsmasq hijack alias, e.g. 192.168.99.5)}"
NET="${NETWORK_WORD:-192.168}"

# Use sudo if not running as root
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

if [ -z "$ACTION" ]; then
    echo "Usage: $0 {hijack|unhijack|block|unblock} <ip_address>"
    echo "       $0 {hijack-blocked-pools|unhijack-blocked-pools}"
    exit 1
fi

case "$ACTION" in
    hijack-blocked-pools|unhijack-blocked-pools)
        # No IP required for pool/VLAN-wide rules
        ;;
    *)
        if [ -z "$IP_ADDRESS" ]; then
            echo "Usage: $0 {hijack|unhijack|block|unblock} <ip_address>"
            echo "       $0 {hijack-blocked-pools|unhijack-blocked-pools}"
            exit 1
        fi
        ;;
esac

CONFIG_PATH="${KEA_CONFIG_PATH:-}"
if [ -z "$CONFIG_PATH" ]; then
    if [ -f "/kea/config/dhcp4.json" ]; then
        CONFIG_PATH="/kea/config/dhcp4.json"
    else
        CONFIG_PATH="/home/admin/bf-network/kea/config/dhcp4.json"
    fi
fi

get_blocked_pool_ranges() {
    if ! command -v python3 >/dev/null 2>&1; then
        return 1
    fi

    python3 - <<'PY' "$CONFIG_PATH"
import json
import ipaddress
import sys

config_path = sys.argv[1]
try:
    with open(config_path, 'r', encoding='utf-8') as handle:
        data = json.load(handle)
except Exception:
    sys.exit(1)

for subnet in data.get('Dhcp4', {}).get('subnet4', []):
    try:
        vlan_id = int(subnet.get('id'))
    except Exception:
        continue
    if vlan_id == 99:
        continue
    blocked_pool = None
    for pool in subnet.get('pools', []):
        classes = pool.get('client-classes') or []
        if 'BLOCKED' in classes:
            blocked_pool = pool.get('pool')
            break
    if not blocked_pool:
        network = ipaddress.ip_network(subnet.get('subnet'), strict=False)
        block_size = 40 * (2 ** (24 - network.prefixlen))
        blocked_start = network.broadcast_address - (block_size - 1)
        blocked_pool = f"{blocked_start}-{network.broadcast_address}"
    else:
        start_str, end_str = [part.strip() for part in blocked_pool.split('-', 1)]
        blocked_pool = f"{start_str}-{end_str}"
    print(f"{vlan_id}|{blocked_pool}")
PY
}

# Validate IP address format (POSIX-compliant)
if [ -n "$IP_ADDRESS" ]; then
    case "$IP_ADDRESS" in
        *[!0-9.]*|*..*|*...*|.*)
            echo "Error: Invalid IP address format: $IP_ADDRESS"
            exit 1
            ;;
    esac
fi

add_blocked_pool_rules() {
    if ranges=$(get_blocked_pool_ranges) && [ -n "$ranges" ]; then
        echo "$ranges" | while IFS='|' read -r VLAN RANGE; do
            [ -z "$VLAN" ] && continue
            [ -z "$RANGE" ] && continue
            $SUDO iptables -t nat -C PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
            if [ $? -ne 0 ]; then
                $SUDO iptables -t nat -A PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53
                echo "DNS hijack enabled for $RANGE (UDP)"
            fi

            $SUDO iptables -t nat -C PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
            if [ $? -ne 0 ]; then
                $SUDO iptables -t nat -A PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53
                echo "DNS hijack enabled for $RANGE (TCP)"
            fi
        done
        return 0
    fi

    VLANS="10 20 30 40 50 60 70 80 90"
    for VLAN in $VLANS; do
        RANGE="${NET}.$VLAN.214-${NET}.$VLAN.254"
        $SUDO iptables -t nat -C PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53
            echo "DNS hijack enabled for $RANGE (UDP)"
        fi

        $SUDO iptables -t nat -C PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53
            echo "DNS hijack enabled for $RANGE (TCP)"
        fi
    done
}

remove_blocked_pool_rules() {
    if ranges=$(get_blocked_pool_ranges) && [ -n "$ranges" ]; then
        echo "$ranges" | while IFS='|' read -r VLAN RANGE; do
            [ -z "$VLAN" ] && continue
            [ -z "$RANGE" ] && continue
            $SUDO iptables -t nat -D PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "DNS hijack removed for $RANGE (UDP)"
            fi

            $SUDO iptables -t nat -D PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "DNS hijack removed for $RANGE (TCP)"
            fi
        done
        return 0
    fi

    VLANS="10 20 30 40 50 60 70 80 90"
    for VLAN in $VLANS; do
        RANGE="${NET}.$VLAN.214-${NET}.$VLAN.254"
        $SUDO iptables -t nat -D PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $RANGE (UDP)"
        fi

        $SUDO iptables -t nat -D PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $RANGE (TCP)"
        fi
    done
}

case "$ACTION" in
    hijack-blocked-pools)
        add_blocked_pool_rules
        ;;

    unhijack-blocked-pools)
        remove_blocked_pool_rules
        ;;

    hijack)
        # Redirect DNS requests from this IP to hijacking DNSmasq ($HIJACK_DNS_IP)
        # When device queries $PORTAL_IP:53, redirect to $HIJACK_DNS_IP:53
        $SUDO iptables -t nat -C PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53
            echo "DNS hijack enabled for $IP_ADDRESS (UDP)"
        fi
        
        $SUDO iptables -t nat -C PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53
            echo "DNS hijack enabled for $IP_ADDRESS (TCP)"
        fi
        ;;
        
    unhijack)
        # Remove DNS redirect rules for this IP
        $SUDO iptables -t nat -D PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $IP_ADDRESS (UDP)"
        fi
        
        $SUDO iptables -t nat -D PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $IP_ADDRESS (TCP)"
        fi
        ;;
        
    block)
        # DNS HIJACKING ONLY - Internet blocking happens via VLAN on HP5130
        # This just hijacks DNS to trigger captive portal detection
        
        $SUDO iptables -t nat -C PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53
            echo "DNS hijack enabled for $IP_ADDRESS (UDP)"
        fi
        
        $SUDO iptables -t nat -C PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53
            echo "DNS hijack enabled for $IP_ADDRESS (TCP)"
        fi
        
        echo "Device $IP_ADDRESS DNS hijacked - actual blocking via VLAN 90 on HP5130"
        ;;
        
    unblock)
        # Remove DNS hijacking only (VLAN change handled by Kea/RADIUS)
        
        $SUDO iptables -t nat -D PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $IP_ADDRESS (UDP)"
        fi
        
        $SUDO iptables -t nat -D PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d "$PORTAL_IP" -j DNAT --to-destination "$HIJACK_DNS_IP":53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $IP_ADDRESS (TCP)"
        fi
        
        echo "Device $IP_ADDRESS DNS unhijacked"
        ;;
        
    *)
        echo "Error: Unknown action '$ACTION'"
        echo "Usage: $0 {hijack|unhijack|block|unblock} <ip_address>"
        exit 1
        ;;
esac
