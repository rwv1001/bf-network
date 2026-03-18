#!/usr/bin/env bash
# hp5130-reip.sh
# Renumbers all HP5130 VLAN interface IPs from 192.168.n.1 → 192.168.n.2
# and updates ACL/RADIUS references accordingly.
#
# IMPORTANT: Run this script from the Pi. It SSHes to the switch via VLAN99
# (192.168.99.1) so VLAN1 can be changed without dropping the session.
# VLAN99 is changed last; the SSH session will drop at that point, which is expected.
# The script then updates the Pi's default gateway and reloads networking.
#
# Usage: sudo bash /home/admin/bf-network/scripts/hp5130-reip.sh

set -euo pipefail

SWITCH_IP="${SWITCH_IP:?SWITCH_IP is required}"   # SSH target – current switch IP before reip
SWITCH_NEW_IP="${SWITCH_HOST:?SWITCH_HOST is required}"  # New VLAN99 address after reip
NET="${NETWORK_WORD:-192.168}"                          # Two-octet network prefix
SW_OCTET="$(echo "${SWITCH_HOST}" | awk -F. '{print $NF}')"   # Host octet from SWITCH_HOST
SWITCH_USER="robert"
SWITCH_KEY="/home/admin/.ssh/id_rsa"
SWITCH_SSH_PORT="22"
GW_NETWORK_FILE="/etc/systemd/network/30-eth0.99.network"

SSH_OPTS=(
  -tt
  -i "$SWITCH_KEY"
  -p "$SWITCH_SSH_PORT"
  -o HostKeyAlgorithms=+ssh-rsa
  -o PubkeyAcceptedAlgorithms=+ssh-rsa
  -o StrictHostKeyChecking=no
  -o ConnectTimeout=10
)

echo "=== HP5130 IP Renumbering Script ==="
echo "Will change all VLAN IPs from ${NET}.n.1 → ${NET}.n.${SW_OCTET}"
echo "SSHing to switch at ${SWITCH_IP} ..."
echo ""

# Send all config commands in one SSH session.
# VLAN99 is changed LAST; 'save force' runs before that so all other
# changes are persisted even if the session drops mid-VLAN99-change.
ssh "${SSH_OPTS[@]}" "${SWITCH_USER}@${SWITCH_IP}" << SWITCH_EOF || true
system-view

interface Vlan-interface1
 ip address ${NET}.1.${SW_OCTET} 255.255.255.0
quit

interface Vlan-interface10
 ip address ${NET}.10.${SW_OCTET} 255.255.255.0
quit

interface Vlan-interface20
 ip address ${NET}.20.${SW_OCTET} 255.255.252.0
quit

interface Vlan-interface30
 ip address ${NET}.30.${SW_OCTET} 255.255.254.0
quit

interface Vlan-interface40
 ip address ${NET}.40.${SW_OCTET} 255.255.255.0
quit

interface Vlan-interface50
 ip address ${NET}.50.${SW_OCTET} 255.255.255.0
quit

interface Vlan-interface60
 ip address ${NET}.60.${SW_OCTET} 255.255.255.0
quit

interface Vlan-interface70
 ip address ${NET}.70.${SW_OCTET} 255.255.255.0
quit

interface Vlan-interface80
 ip address ${NET}.80.${SW_OCTET} 255.255.255.0
quit

interface Vlan-interface250
 ip address ${NET}.250.${SW_OCTET} 255.255.255.0
quit

acl number 3000 name PREAUTH
 undo rule 12
 rule 12 permit ip destination ${NET}.250.${SW_OCTET} 0
quit

radius scheme rad1
 nas-ip ${SWITCH_HOST}
quit

return
save force

system-view
interface Vlan-interface99
 ip address ${SWITCH_HOST} 255.255.255.0
return

SWITCH_EOF

# SSH will have dropped when VLAN99 IP changed — that's expected.
echo ""
echo "=== Switch SSH session ended (expected if VLAN99 changed) ==="
echo ""

# Give the switch a moment to finish processing and save
sleep 3

# Update the Pi's default gateway to point at the new VLAN99 IP
echo "Updating Pi gateway: ${GW_NETWORK_FILE}"
if [[ ! -f "$GW_NETWORK_FILE" ]]; then
  echo "ERROR: ${GW_NETWORK_FILE} not found — update Gateway manually!"
  exit 1
fi

sudo sed -i "s/Gateway=${SWITCH_IP}/Gateway=${SWITCH_NEW_IP}/" "$GW_NETWORK_FILE"
echo "Gateway updated in ${GW_NETWORK_FILE}"

echo "Reloading systemd-networkd..."
sudo networkctl reload
sleep 2

echo ""
echo "=== Verifying new gateway ==="
ip route show default
echo ""

echo "=== Testing connectivity to switch at new IP (${SWITCH_NEW_IP}) ==="
if ping -c 3 -W 2 "${SWITCH_NEW_IP}" &>/dev/null; then
  echo "SUCCESS: Switch is reachable at ${SWITCH_NEW_IP}"
else
  echo "WARNING: Switch not yet responding at ${SWITCH_NEW_IP}"
  echo "It may still be saving/rebooting. Wait 30s and try: ping ${SWITCH_NEW_IP}"
fi

echo ""
echo "=== Done ==="
echo "Next steps:"
echo "  1. Update kea/.env: SWITCH_HOST=192.168.1.2"
echo "  2. Update captive-portal/.env: SWITCH_HOST=192.168.1.2"
echo "  3. Update kea/config/dhcp4.json: all routers from .n.1 -> .n.2"
echo "  4. Restart kea and captive-portal containers"
