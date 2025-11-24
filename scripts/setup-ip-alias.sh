#!/bin/bash
# Add persistent IP alias for hijacking DNSmasq
# 192.168.99.5 will be used for DNS hijacking of unregistered devices

ip addr add 192.168.99.5/32 dev eth0.99 2>/dev/null || true
echo "IP alias 192.168.99.5 added to eth0.99"
