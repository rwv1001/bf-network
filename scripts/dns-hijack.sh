#!/bin/sh
# DNS Hijacking Management Script
# Redirects DNS requests from unregistered devices to hijacking DNSmasq (192.168.99.5)

ACTION="$1"
IP_ADDRESS="$2"

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
        # No IP required for blocked pool range rules
        ;;
    *)
        if [ -z "$IP_ADDRESS" ]; then
            echo "Usage: $0 {hijack|unhijack|block|unblock} <ip_address>"
            echo "       $0 {hijack-blocked-pools|unhijack-blocked-pools}"
            exit 1
        fi
        ;;
esac

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
    VLANS="10 20 30 40 50 60 70 90"
    for VLAN in $VLANS; do
        RANGE="192.168.$VLAN.214-192.168.$VLAN.254"
        $SUDO iptables -t nat -C PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53
            echo "DNS hijack enabled for $RANGE (UDP)"
        fi

        $SUDO iptables -t nat -C PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53
            echo "DNS hijack enabled for $RANGE (TCP)"
        fi
    done
}

remove_blocked_pool_rules() {
    VLANS="10 20 30 40 50 60 70 90"
    for VLAN in $VLANS; do
        RANGE="192.168.$VLAN.214-192.168.$VLAN.254"
        $SUDO iptables -t nat -D PREROUTING -m iprange --src-range "$RANGE" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $RANGE (UDP)"
        fi

        $SUDO iptables -t nat -D PREROUTING -m iprange --src-range "$RANGE" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
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
        # Redirect DNS requests from this IP to hijacking DNSmasq (192.168.99.5)
        # When device queries 192.168.99.4:53, redirect to 192.168.99.5:53
        $SUDO iptables -t nat -C PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53
            echo "DNS hijack enabled for $IP_ADDRESS (UDP)"
        fi
        
        $SUDO iptables -t nat -C PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53
            echo "DNS hijack enabled for $IP_ADDRESS (TCP)"
        fi
        ;;
        
    unhijack)
        # Remove DNS redirect rules for this IP
        $SUDO iptables -t nat -D PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $IP_ADDRESS (UDP)"
        fi
        
        $SUDO iptables -t nat -D PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $IP_ADDRESS (TCP)"
        fi
        ;;
        
    block)
        # DNS HIJACKING ONLY - Internet blocking happens via VLAN on HP5130
        # This just hijacks DNS to trigger captive portal detection
        
        $SUDO iptables -t nat -C PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53
            echo "DNS hijack enabled for $IP_ADDRESS (UDP)"
        fi
        
        $SUDO iptables -t nat -C PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -ne 0 ]; then
            $SUDO iptables -t nat -A PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53
            echo "DNS hijack enabled for $IP_ADDRESS (TCP)"
        fi
        
        echo "Device $IP_ADDRESS DNS hijacked - actual blocking via VLAN 90 on HP5130"
        ;;
        
    unblock)
        # Remove DNS hijacking only (VLAN change handled by Kea/RADIUS)
        
        $SUDO iptables -t nat -D PREROUTING -s "$IP_ADDRESS" -p udp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "DNS hijack removed for $IP_ADDRESS (UDP)"
        fi
        
        $SUDO iptables -t nat -D PREROUTING -s "$IP_ADDRESS" -p tcp --dport 53 -d 192.168.99.4 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null
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
