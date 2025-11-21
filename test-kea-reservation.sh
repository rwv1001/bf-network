#!/bin/bash
# Test Kea dynamic reservations

MAC="7e:cd:4b:4e:fa:f3"
SUBNET=10
IP="192.168.10.100"
SOCKET="/home/admin/bf-network/kea/sockets/kea4-ctrl-socket"

echo "=== Testing Kea Dynamic Reservation System ==="
echo ""

# 1. Check if reservation exists
echo "1. Checking for existing reservation..."
RESULT=$(echo "{\"command\":\"reservation-get\",\"arguments\":{\"subnet-id\":$SUBNET,\"identifier-type\":\"hw-address\",\"identifier\":\"$MAC\"}}" | nc -U $SOCKET)
echo "$RESULT" | python3 -m json.tool
echo ""

# 2. Show current lease
echo "2. Current leases for device:"
grep "$MAC" /home/admin/bf-network/kea/leases/kea-leases4.csv | tail -3
echo ""

# 3. Check database
echo "3. Database reservation:"
cd /home/admin/bf-network/captive-portal && docker compose exec -T db psql -U portal_user -d captive_portal -c "SELECT host_id, encode(dhcp_identifier, 'hex') as mac, dhcp4_subnet_id, ipv4_address, dhcp4_client_classes FROM hosts WHERE encode(dhcp_identifier, 'hex') = '7ecd4b4efaf3';"
echo ""

echo "=== To test: Disconnect phone from WiFi, wait 10 seconds, reconnect ==="
echo "Then check if it gets IP $IP with 24-hour lease"
