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

SWITCH_IP="192.168.99.1"   # SSH via VLAN99 so we can change VLAN1 without losing session
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
echo "Will change all VLAN IPs from 192.168.n.1 → 192.168.n.2"
echo "SSHing to switch at ${SWITCH_IP} ..."
echo ""

# Send all config commands in one SSH session.
# VLAN99 is changed LAST; 'save force' runs before that so all other
# changes are persisted even if the session drops mid-VLAN99-change.
ssh "${SSH_OPTS[@]}" "${SWITCH_USER}@${SWITCH_IP}" << 'SWITCH_EOF' || true
system-view

interface Vlan-interface1
 ip address 192.168.1.2 255.255.255.0
quit

interface Vlan-interface10
 ip address 192.168.10.2 255.255.255.0
quit

interface Vlan-interface20
 ip address 192.168.20.2 255.255.252.0
quit

interface Vlan-interface30
 ip address 192.168.30.2 255.255.254.0
quit

interface Vlan-interface40
 ip address 192.168.40.2 255.255.255.0
quit

interface Vlan-interface50
 ip address 192.168.50.2 255.255.255.0
quit

interface Vlan-interface60
 ip address 192.168.60.2 255.255.255.0
quit

interface Vlan-interface70
 ip address 192.168.70.2 255.255.255.0
quit

interface Vlan-interface80
 ip address 192.168.80.2 255.255.255.0
quit

interface Vlan-interface250
 ip address 192.168.250.2 255.255.255.0
quit

acl number 3000 name PREAUTH
 undo rule 12
 rule 12 permit ip destination 192.168.250.2 0
quit

radius scheme rad1
 nas-ip 192.168.99.2
quit

return
save force

system-view
interface Vlan-interface99
 ip address 192.168.99.2 255.255.255.0
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

sudo sed -i 's/Gateway=192\.168\.99\.1/Gateway=192.168.99.2/' "$GW_NETWORK_FILE"
echo "Gateway updated in ${GW_NETWORK_FILE}"

echo "Reloading systemd-networkd..."
sudo networkctl reload
sleep 2

echo ""
echo "=== Verifying new gateway ==="
ip route show default
echo ""

echo "=== Testing connectivity to switch at new IP (192.168.99.2) ==="
if ping -c 3 -W 2 192.168.99.2 &>/dev/null; then
  echo "SUCCESS: Switch is reachable at 192.168.99.2"
else
  echo "WARNING: Switch not yet responding at 192.168.99.2"
  echo "It may still be saving/rebooting. Wait 30s and try: ping 192.168.99.2"
fi

echo ""
echo "=== Done ==="
echo "Next steps:"
echo "  1. Update kea/.env: SWITCH_HOST=192.168.1.2"
echo "  2. Update captive-portal/.env: SWITCH_HOST=192.168.1.2"
echo "  3. Update kea/config/dhcp4.json: all routers from .n.1 -> .n.2"
echo "  4. Restart kea and captive-portal containers"
