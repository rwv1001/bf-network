#!/bin/bash
# hp5130-setup-sw2.sh
#
# Stage 2: Configure second HP5130 switch from scratch.
#
# Prerequisites:
#   - SW2 reachable via SSH at SW2_HOST (default 192.168.1.3), admin password auth
#   - SW1 reachable via SSH key at SW1_HOST (default 192.168.99.2), robert key auth
#   - sshpass installed: sudo apt-get install sshpass
#   - freeradius/.env contains RADIUS_SECRET
#
# What this script does:
#   Phase 1 – SSH to SW2 (password): configure sysname, VLANs, VLAN-interface IPs,
#             RADIUS, CoA, PI_KEY / robert SSH user, NTP, default route, ACL 3000/3099,
#             portal settings, trunk port on SW2, scheduler backup, save force
#   Phase 2 – SSH to SW1 (key):      configure Ten-GigabitEthernet1/0/28 as trunk to SW2
#   Phase 3 – Run hp5130-acl-baseline.sh against SW2 via key (now at 192.168.99.3)
#
# Access ports (GigabitEthernet3/0/1..N) are NOT configured here.
# Run hp5130-acl-baseline.sh first, then configure each port manually or via a
# separate script once you know the exact port numbering.

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────────────
SW2_HOST="${SW2_HOST:-192.168.1.3}"
SW2_USER="${SW2_USER:-admin}"
SW1_HOST="${SW1_HOST:-192.168.99.2}"
SW1_USER="${SW1_USER:-robert}"
KEY="${KEY:-/home/admin/.ssh/id_rsa}"

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
read -s -p "Enter admin password for SW2 ($SW2_HOST): " SW2_PASS
echo
export SSHPASS="$SW2_PASS"

SSH_PW_OPTS="-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH_KEY_OPTS="-i $KEY $SSH_PW_OPTS"

# ─── Phase 1: Configure SW2 ──────────────────────────────────────────────────
echo ""
echo "=== Phase 1: Configuring SW2 ($SW2_HOST) via password SSH ==="

# PI_KEY hex bytes (DER-encoded RSA public key, same as installed on SW1)
PI_KEY_HEX='  30820122300D06092A864886F70D01010105000382010F003082010A0282010100CA914037
  AB50CBD4757E01A542EDFCF91A8CCA218A33F76CE4E4490EB9A31097E52DF9C420D207DEA3
  64186ABEEF5DE5A861F0E6DA8E399A4CE5611CFE033F52C87F12CB7C4E95BD0F5F3D3B4808
  78D79B9D6DA56866604F3B0D28D3319BA05E1D51C390F26C74C8CD14B39C2F46A8BCF2964F
  DC060CA772AD8987AEE38181900C5C1673F7E350CF65E26F5E56BBA5D83A0BE95DC1C50457
  A3FE1AFB323FE839DDCA10746890FDB9AC32364C62626042185C06B6542DE67D3C768A451F
  A5EA8B35C6D601C7DEF36CADD7E1F21E82118C8A7C980558FCD7666A355A5B9058265C8D63
  BBF6AF18A6A5E4495D64F42617492DACE0701729306DB08C7FCCEAD1434B0203010001'

SW2_CMDS=$(cat <<ENDSW2
system-view
#
sysname AccessSW-02
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
web-auth free-ip 192.168.99.4 255.255.255.255
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
 ip address 192.168.10.3 255.255.255.0
quit
interface Vlan-interface20
 description GW_VLAN20
 ip address 192.168.20.3 255.255.252.0
quit
interface Vlan-interface30
 description GW_VLAN30
 ip address 192.168.30.3 255.255.254.0
quit
interface Vlan-interface40
 description GW_VLAN40
 ip address 192.168.40.3 255.255.255.0
quit
interface Vlan-interface50
 description GW_VLAN50
 ip address 192.168.50.3 255.255.255.0
quit
interface Vlan-interface60
 description GW_VLAN60
 ip address 192.168.60.3 255.255.255.0
quit
interface Vlan-interface70
 description GW_VLAN70
 ip address 192.168.70.3 255.255.255.0
quit
interface Vlan-interface80
 description GW_VLAN80
 ip address 192.168.80.3 255.255.255.0
quit
interface Vlan-interface90
quit
interface Vlan-interface99
 description GW_VLAN99
 ip address 192.168.99.3 255.255.255.0
quit
interface Vlan-interface250
 description GW_VLAN250
 ip address 192.168.250.3 255.255.255.0
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
 primary authentication 192.168.99.4
 primary accounting 192.168.99.4
 key authentication simple $RADIUS_SECRET
 key accounting simple $RADIUS_SECRET
 user-name-format without-domain
 nas-ip 192.168.99.3
quit
#
radius dynamic-author server
 client ip 192.168.99.4 key simple $RADIUS_SECRET
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
 rule 5 permit udp destination 192.168.99.4 0 destination-port eq dns
 rule 6 permit tcp destination 192.168.99.4 0 destination-port eq dns
 rule 7 permit udp destination 192.168.99.5 0 destination-port eq dns
 rule 8 permit tcp destination 192.168.99.5 0 destination-port eq dns
 rule 9 permit icmp destination 192.168.99.5 0
 rule 10 permit tcp destination 192.168.99.4 0 destination-port eq www
 rule 11 permit tcp destination 192.168.99.4 0 destination-port eq 443
 rule 12 permit ip destination 192.168.250.4 0
 rule 100 deny ip
quit
acl number 3099 name VLAN99_EGRESS
 rule 0 permit ip source 192.168.99.0 0.0.0.255 destination 192.168.1.0 0.0.0.255
 rule 1 permit ip source 192.168.99.4 0
 rule 2 permit ip source 192.168.99.0 0.0.0.255
 rule 5 deny ip source 192.168.99.0 0.0.0.255
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
 url https://bf-network.duckdns.org/register/
quit
web-auth server PI-PORTAL
 url http://192.168.99.4:8080/register/
 ip 192.168.99.4 port 8080
quit
portal free-rule 30 destination ip 192.168.99.4 255.255.255.255 tcp 443
#
arp detection validate dst-mac ip src-mac
#
ntp-service enable
ntp-service source Vlan-interface1
ntp-service unicast-server 192.168.99.4
ntp-service unicast-server 162.159.200.1
#
ip route-static 0.0.0.0 0 192.168.1.1
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
 command 2 tftp 192.168.99.4 put flash:/startup.cfg 5130-startup-sw2.cfg
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
ENDSW2
)

set +e
printf '%s' "$SW2_CMDS" | \
    timeout 30 sshpass -e ssh -tt $SSH_PW_OPTS "${SW2_USER}@${SW2_HOST}"
PHASE1_EC=$?
set -e
# exit 124 = timeout (all commands ran, switch held session open) - treat as success
if [ "$PHASE1_EC" -ne 0 ] && [ "$PHASE1_EC" -ne 124 ]; then
    echo "ERROR: Phase 1 failed (exit $PHASE1_EC). Check password and connectivity to $SW2_HOST."
    exit 1
fi

echo ""
echo "=== Phase 1 complete. SW2 configured. SSH key installed. ==="
echo "    SW2 management IP is now 192.168.99.3"
echo ""
sleep 3   # Give the switch time to finish saving

# ─── Phase 2: Configure SW1 trunk to SW2 ─────────────────────────────────────
echo "=== Phase 2: Configuring SW1 trunk port Ten-GigabitEthernet1/0/28 ==="

SW1_TRUNK_CMDS=$(cat <<'ENDSW1'
system-view
interface Ten-GigabitEthernet1/0/28
 description TRUNK-TO-SW2
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
echo "=== Phase 2 complete. SW1 trunk port Ten-GigabitEthernet1/0/28 configured. ==="
echo ""

# ─── Phase 3: Run ACL baseline on SW2 ────────────────────────────────────────
echo "=== Phase 3: Running ACL baseline against SW2 (192.168.99.3) ==="

SWITCH_HOST=192.168.99.3 \
SWITCH_USER=robert \
SWITCH_KEY_PATH="$KEY" \
    bash "$SCRIPT_DIR/hp5130-acl-baseline.sh" || {
    echo "ERROR: Phase 3 (ACL baseline) failed."
    exit 1
}

echo ""
echo "=== Phase 3 complete. ACLs configured on SW2. ==="
echo ""
echo "================================================================"
echo " Stage 2 complete!"
echo ""
echo " Summary:"
echo "   SW2 VLAN99 management IP : 192.168.99.3"
echo "   SW2 VLAN1 management IP  : 192.168.1.3"
echo "   SSH as robert (key auth) : ssh -i $KEY -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa robert@192.168.99.3"
echo ""
echo " Next steps:"
echo "   1. Verify: ssh robert@192.168.99.3 and run 'display version'"
echo "   2. Configure access ports (GigabitEthernet3/0/1..N) for mac-auth"
echo "      (see SW1's running config as a template)"
echo "   3. Connect APs and test WiFi registration via SW2"
echo "================================================================"
