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

if [ -z "$ACTION" ] || [ -z "$IP_ADDRESS" ]; then
    echo "Usage: $0 {hijack|unhijack} <ip_address>"
    exit 1
fi

# Validate IP address format (POSIX-compliant)
case "$IP_ADDRESS" in
    *[!0-9.]*|*..*|*...*|.*)
        echo "Error: Invalid IP address format: $IP_ADDRESS"
        exit 1
        ;;
esac

case "$ACTION" in
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
        
    *)
        echo "Error: Unknown action '$ACTION'"
        echo "Usage: $0 {hijack|unhijack} <ip_address>"
        exit 1
        ;;
esac
