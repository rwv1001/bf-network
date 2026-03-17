#!/bin/bash
# Add persistent IP alias for DNS hijacking
# HIJACK_DNS_IP is used for DNS hijacking of unregistered devices
HIJACK_DNS_IP="${HIJACK_DNS_IP:?HIJACK_DNS_IP required}"
MGMT_IFACE="${MGMT_IFACE:-eth0.99}"

ip addr add "${HIJACK_DNS_IP}/32" dev "$MGMT_IFACE" 2>/dev/null || true
echo "IP alias ${HIJACK_DNS_IP} added to ${MGMT_IFACE}"
