#!/bin/bash
# hp5130-setup-switch.sh
#
# Configure an additional HP5130 switch from scratch.
# Can be run for any switch in SWITCH_HOSTS.
#
# Prerequisites:
#   - Target switch reachable via SSH at TARGET_HOST (factory/current IP), admin password auth
#   - Primary switch (SW1) reachable via SSH key at SW1_HOST, robert key auth
#   - sshpass installed: sudo apt-get install sshpass
#   - freeradius/.env contains RADIUS_SECRET
#
# Required environment variables:
#   TARGET_HOST        – current IP to SSH to (e.g. 192.168.1.3, factory default)
#   TARGET_IP          – final VLAN-99 management IP (e.g. 192.168.99.6)
#   SW1_HOST           – primary switch management IP (already configured)
#   SW1_TRUNK_PORT     – port on SW1 to configure as trunk to this switch
#                        (e.g. Ten-GigabitEthernet1/0/28)
#   PORTAL_IP, HIJACK_DNS_IP, MGMT_GATEWAY, RADIUS_SECRET
#
# What this script does:
#   Phase 1 – SSH to target (password): configure sysname, VLANs, VLAN-interface IPs,
#             RADIUS, CoA, PI_KEY / robert SSH user, NTP, default route, ACL 3000/3099,
#             portal settings, trunk port, scheduler backup, save force
#   Phase 2 – SSH to SW1 (key):         configure SW1_TRUNK_PORT as trunk to this switch
#   Phase 3 – Run hp5130-acl-baseline.sh against the new switch (at TARGET_IP)
#
# Access ports (GigabitEthernet3/0/1..N) are NOT configured here.
# Run hp5130-acl-baseline.sh first, then configure each port manually or via a
# separate script once you know the exact port numbering.

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────────────
TARGET_HOST="${TARGET_HOST:?TARGET_HOST is required (initial/factory IP of the switch to configure)}"
TARGET_USER="${TARGET_USER:-admin}"
SW1_HOST="${SW1_HOST:?SW1_HOST is required (primary switch management IP)}"
SW1_USER="${SW1_USER:-robert}"
SW1_TRUNK_PORT="${SW1_TRUNK_PORT:?SW1_TRUNK_PORT is required (e.g. Ten-GigabitEthernet1/0/28)}"
KEY="${KEY:-/home/admin/.ssh/id_rsa}"

# Site-specific IPs (must be set in environment or captive-portal/.env)
PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
HIJACK_DNS_IP="${HIJACK_DNS_IP:?HIJACK_DNS_IP required}"
TARGET_IP="${TARGET_IP:?TARGET_IP is required (final VLAN-99 management IP for this switch)}"
MGMT_GATEWAY="${MGMT_GATEWAY:?MGMT_GATEWAY is required}" # Default gateway for management VLAN
NET="${NETWORK_WORD:-192.168}"                  # Two-octet network prefix
SW_OCTET="$(echo "${TARGET_IP}" | awk -F. '{print $NF}')"   # Host octet derived from TARGET_IP
SW_SYSNAME="AccessSW-$(printf '%02d' "${SW_OCTET}")"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Load RADIUS_SECRET ───────────────────────────────────────────────────────
if [ -z "${RADIUS_SECRET:-}" ]; then
    ENV_FILE="$SCRIPT_DIR/../freeradius/.env"
    if [ -f "$ENV_FILE" ]; then
        RADIUS_SECRET=$(grep '^RADIUS_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '\r\n')
    fi
fi
if [ -z "${RADIUS_SECRET:-}" ]; then
    echo "ERROR: RADIUS_SECRET not set. Add it to freeradius/.env or export it."
    exit 1
fi

# ─── Check sshpass ────────────────────────────────────────────────────────────
if ! command -v sshpass &>/dev/null; then
    echo "ERROR: sshpass is required for the initial password-based SSH connection."
    echo "       Install with: sudo apt-get install sshpass"
    exit 1
fi

# ─── Read admin password ─────────────────────────────────────────────────────
read -s -p "Enter admin password for target switch ($TARGET_HOST): " TARGET_PASS
echo
export SSHPASS="$TARGET_PASS"

SSH_PW_OPTS="-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH_KEY_OPTS="-i $KEY $SSH_PW_OPTS"

# ─── Phase 1: Configure target switch ───────────────────────────────────────
echo ""
echo "=== Phase 1: Configuring ${SW_SYSNAME} ($TARGET_HOST → ${TARGET_IP}) via password SSH ==="

# PI_KEY hex bytes (DER-encoded RSA public key, same as installed on SW1)
PI_KEY_HEX='  30820122300D06092A864886F70D01010105000382010F003082010A0282010100CA914037
  AB50CBD4757E01A542EDFCF91A8CCA218A33F76CE4E4490EB9A31097E52DF9C420D207DEA3
  64186ABEEF5DE5A861F0E6DA8E399A4CE5611CFE033F52C87F12CB7C4E95BD0F5F3D3B4808
  78D79B9D6DA56866604F3B0D28D3319BA05E1D51C390F26C74C8CD14B39C2F46A8BCF2964F
  DC060CA772AD8987AEE38181900C5C1673F7E350CF65E26F5E56BBA5D83A0BE95DC1C50457
  A3FE1AFB323FE839DDCA10746890FDB9AC32364C62626042185C06B6542DE67D3C768A451F
  A5EA8B35C6D601C7DEF36CADD7E1F21E82118C8A7C980558FCD7666A355A5B9058265C8D63
  BBF6AF18A6A5E4495D64F42617492DACE0701729306DB08C7FCCEAD1434B0203010001'

SW_CMDS=$(cat <<ENDSW
system-view
#
sysname ${SW_SYSNAME}
#
clock timezone GMT add 00:00:00
clock summer-time BST 01:00:00 March last Sunday 02:00:00 October last Sunday 01:00:00
#
irf mac-address persistent timer
irf auto-update enable
undo irf link-delay
irf member 1 priority 1
#
mac-authentication domain macauth
#
web-auth free-ip ${PORTAL_IP} 255.255.255.255
#
port-security enable
#
dhcp snooping enable
dhcp snooping enable vlan 10 20 30 40 50 60 70 80 90 250
#
dns proxy enable
dns source-interface Vlan-interface1
dns server 1.1.1.1
dns server 8.8.8.8
#
lldp global enable
#
password-recovery enable
#
stp global enable
#
vlan 10
 name friars
 dhcp snooping binding record
 arp detection enable
quit
vlan 20
 name staff
 dhcp snooping binding record
 arp detection enable
quit
vlan 30
 name students
 dhcp snooping binding record
 arp detection enable
quit
vlan 40
 name guests
 dhcp snooping binding record
 arp detection enable
quit
vlan 50
 name contractors
 dhcp snooping binding record
 arp detection enable
quit
vlan 60
 name iot
 dhcp snooping binding record
 arp detection enable
quit
vlan 70
 name wifi-registered
 dhcp snooping binding record
 arp detection enable
quit
vlan 80
 name kiosk
 dhcp snooping binding record
 arp detection enable
quit
vlan 90
 name printers
 dhcp snooping binding record
 arp detection enable
quit
vlan 99
 name management
quit
vlan 250
 name unregistered
 dhcp snooping binding record
quit
#
interface Vlan-interface1
 description GW_VLAN1_FROM_5130
quit
interface Vlan-interface10
 description GW_VLAN10
 ip address ${NET}.10.${SW_OCTET} 255.255.255.0
quit
interface Vlan-interface20
 description GW_VLAN20
 ip address ${NET}.20.${SW_OCTET} 255.255.252.0
quit
interface Vlan-interface30
 description GW_VLAN30
 ip address ${NET}.30.${SW_OCTET} 255.255.254.0
quit
interface Vlan-interface40
 description GW_VLAN40
 ip address ${NET}.40.${SW_OCTET} 255.255.255.0
quit
interface Vlan-interface50
 description GW_VLAN50
 ip address ${NET}.50.${SW_OCTET} 255.255.255.0
quit
interface Vlan-interface60
 description GW_VLAN60
 ip address ${NET}.60.${SW_OCTET} 255.255.255.0
quit
interface Vlan-interface70
 description GW_VLAN70
 ip address ${NET}.70.${SW_OCTET} 255.255.255.0
quit
interface Vlan-interface80
 description GW_VLAN80
 ip address ${NET}.80.${SW_OCTET} 255.255.255.0
quit
interface Vlan-interface90
quit
interface Vlan-interface99
 description GW_VLAN99
 ip address ${TARGET_IP} 255.255.255.0
quit
interface Vlan-interface250
 description GW_VLAN250
 ip address ${NET}.250.${SW_OCTET} 255.255.255.0
quit
#
interface Ten-GigabitEthernet3/0/52
 description TRUNK-TO-SW1
 port link-type trunk
 port trunk permit vlan 1 10 20 30 40 50 60 70 80 90 99
 port trunk permit vlan 250
 arp detection trust
 dhcp snooping trust
quit
#
# Lock management logins to local auth BEFORE configuring RADIUS.
# Without this the switch re-evaluates the VTY auth policy when
# radius scheme rad1 is created and kills the current SSH session.
domain system
 authentication login local
 authorization login local
quit
#
radius scheme rad1
 primary authentication ${PORTAL_IP}
 primary accounting ${PORTAL_IP}
 key authentication simple $RADIUS_SECRET
 key accounting simple $RADIUS_SECRET
 user-name-format without-domain
 nas-ip ${TARGET_IP}
quit
#
radius dynamic-author server
 client ip ${PORTAL_IP} key simple $RADIUS_SECRET
quit
#
domain macauth
 authentication lan-access radius-scheme rad1
 authorization lan-access radius-scheme rad1
 accounting lan-access radius-scheme rad1
 authentication portal radius-scheme rad1
 authorization portal radius-scheme rad1
 accounting portal radius-scheme rad1
quit
#
domain default enable system
#
acl number 3000 name PREAUTH
 rule 1 permit udp source-port eq bootpc destination-port eq bootps
 rule 2 permit udp source-port eq bootps destination-port eq bootpc
 rule 5 permit udp destination ${PORTAL_IP} 0 destination-port eq dns
 rule 6 permit tcp destination ${PORTAL_IP} 0 destination-port eq dns
 rule 7 permit udp destination ${HIJACK_DNS_IP} 0 destination-port eq dns
 rule 8 permit tcp destination ${HIJACK_DNS_IP} 0 destination-port eq dns
 rule 9 permit icmp destination ${HIJACK_DNS_IP} 0
 rule 10 permit tcp destination ${PORTAL_IP} 0 destination-port eq www
 rule 11 permit tcp destination ${PORTAL_IP} 0 destination-port eq 443
 rule 12 permit ip destination ${NET}.250.4 0
 rule 100 deny ip
quit
acl number 3099 name VLAN99_EGRESS
 rule 0 permit ip source ${NET}.99.0 0.0.0.255 destination ${NET}.1.0 0.0.0.255
 rule 1 permit ip source ${PORTAL_IP} 0
 rule 2 permit ip source ${NET}.99.0 0.0.0.255
 rule 5 deny ip source ${NET}.99.0 0.0.0.255
 rule 100 permit ip
quit
#
interface Vlan-interface250
 packet-filter 3000 inbound
quit
interface Vlan-interface99
 packet-filter 3099 inbound
 packet-filter 3099 outbound
quit
#
portal web-server piportal
 url http://${PORTAL_IP}:8080/register/
quit
web-auth server PI-PORTAL
 url http://${PORTAL_IP}:8080/register/
 ip ${PORTAL_IP} port 8080
quit
portal free-rule 30 destination ip ${PORTAL_IP} 255.255.255.255 tcp 443
#
arp detection validate dst-mac ip src-mac
#
ntp-service enable
ntp-service source Vlan-interface1
ntp-service unicast-server ${PORTAL_IP}
ntp-service unicast-server 162.159.200.1
#
ip route-static 0.0.0.0 0 ${MGMT_GATEWAY}
#
ssh server enable
scp server enable
ssh user admin service-type stelnet authentication-type password
#
line vty 0 4
 authentication-mode scheme
 user-role network-admin
 protocol inbound ssh
 idle-timeout 15 0
quit
line vty 5 63
 authentication-mode scheme
 user-role network-admin
quit
#
local-user admin class manage
 service-type ssh terminal
 authorization-attribute user-role network-admin
quit
local-user robert class manage
 service-type ssh
 authorization-attribute user-role network-admin
 authorization-attribute user-role network-operator
quit
#
public-key peer PI_KEY
 public-key-code begin
$PI_KEY_HEX
 public-key-code end
 peer-public-key end
ssh user robert service-type stelnet authentication-type publickey assign publickey PI_KEY
#
password-control enable
undo password-control aging enable
undo password-control length enable
undo password-control composition enable
undo password-control history enable
password-control login-attempt 3 exceed unlock
password-control update-interval 0
password-control login idle-time 0
#
netconf ssh server enable
#
scheduler job backup-config
 command 1 save safely force
 command 2 tftp ${PORTAL_IP} put flash:/startup.cfg 5130-startup-${SW_SYSNAME}.cfg
quit
scheduler schedule nightly-backup
 user-role network-admin
 job backup-config
 time repeating at 03:15
quit
#
save force
quit
quit
ENDSW
)

set +e
printf '%s' "$SW_CMDS" | \
    timeout 30 sshpass -e ssh -tt $SSH_PW_OPTS "${TARGET_USER}@${TARGET_HOST}"
PHASE1_EC=$?
set -e
# exit 124 = timeout (all commands ran, switch held session open) - treat as success
if [ "$PHASE1_EC" -ne 0 ] && [ "$PHASE1_EC" -ne 124 ]; then
    echo "ERROR: Phase 1 failed (exit $PHASE1_EC). Check password and connectivity to $TARGET_HOST."
    exit 1
fi

echo ""
echo "=== Phase 1 complete. ${SW_SYSNAME} configured. SSH key installed. ==="
echo "    Management IP is now ${TARGET_IP}"
echo ""
sleep 3   # Give the switch time to finish saving

# ─── Phase 2: Configure SW1 trunk to new switch ─────────────────────────────
echo "=== Phase 2: Configuring SW1 trunk port ${SW1_TRUNK_PORT} → ${SW_SYSNAME} ==="

SW1_TRUNK_CMDS=$(cat <<ENDSW1
system-view
interface ${SW1_TRUNK_PORT}
 description TRUNK-TO-${SW_SYSNAME}
 port link-type trunk
 port trunk permit vlan 1 10 20 30 40 50 60 70 80 90 99
 port trunk permit vlan 250
 arp detection trust
 dhcp snooping trust
quit
save force
quit
quit
ENDSW1
)

set +e
printf '%s' "$SW1_TRUNK_CMDS" | \
    timeout 60 ssh -tt $SSH_KEY_OPTS "${SW1_USER}@${SW1_HOST}"
PHASE2_EC=$?
set -e
if [ "$PHASE2_EC" -ne 0 ] && [ "$PHASE2_EC" -ne 124 ]; then
    echo "ERROR: Phase 2 failed (exit $PHASE2_EC). Check SW1 connectivity."
    exit 1
fi

echo ""
echo "=== Phase 2 complete. SW1 trunk port ${SW1_TRUNK_PORT} configured. ==="
echo ""

# ─── Phase 3: Run ACL baseline on new switch ─────────────────────────────────
echo "=== Phase 3: Running ACL baseline against ${SW_SYSNAME} (${TARGET_IP}) ==="

SWITCH_HOSTS=${TARGET_IP} \
SWITCH_USER=robert \
SWITCH_KEY_PATH="$KEY" \
    bash "$SCRIPT_DIR/hp5130-acl-baseline.sh" || {
    echo "ERROR: Phase 3 (ACL baseline) failed."
    exit 1
}

echo ""
echo "=== Phase 3 complete. ACLs configured on ${SW_SYSNAME}. ==="
echo ""
echo "================================================================"
echo " Setup complete!"
echo ""
echo " Summary:"
echo "   Switch sysname           : ${SW_SYSNAME}"
echo "   VLAN99 management IP     : ${TARGET_IP}"
echo "   Initial IP (factory)     : ${TARGET_HOST}"
echo "   SSH as robert (key auth) : ssh -i $KEY -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa robert@${TARGET_IP}"
echo ""
echo " Next steps:"
echo "   1. Verify: ssh robert@${TARGET_IP} and run 'display version'"
echo "   2. Add ${TARGET_IP} to SWITCH_HOSTS in captive-portal/.env and kea/.env"
echo "   3. Configure access ports (GigabitEthernet3/0/1..N) for mac-auth"
echo "      (see SW1's running config as a template)"
echo "   3. Connect APs and test WiFi registration via ${SW_SYSNAME}"
echo "================================================================"
