#!/bin/sh
set -eu

SWITCH_HOST="${SWITCH_HOST:-192.168.1.3}"
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-/home/admin/.ssh/id_rsa}"
PORTAL_IP="${PORTAL_IP:-192.168.99.4}"
VLAN_LIST="${VLAN_LIST:-10 20 30 40 50 60 70 90}"

SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

build_acl_commands() {
  VLAN_ID="$1"
  ACL_NUM=$((3000 + VLAN_ID * 10))
  VLAN_NET="192.168.${VLAN_ID}.0"

  cat <<EOF
undo acl advanced ${ACL_NUM}
acl advanced ${ACL_NUM} match-order config
description "VLAN${VLAN_ID} Walled Garden and Full Access"
rule 10 permit udp source ${VLAN_NET} 0.0.0.255 destination 255.255.255.255 0 destination-port eq bootps
rule 11 permit udp source ${VLAN_NET} 0.0.0.255 destination 255.255.255.255 0 destination-port eq bootpc
rule 20 permit udp source ${VLAN_NET} 0.0.0.255 destination ${PORTAL_IP} 0 destination-port eq dns
rule 21 permit tcp source ${VLAN_NET} 0.0.0.255 destination ${PORTAL_IP} 0 destination-port eq dns
rule 30 permit tcp source ${VLAN_NET} 0.0.0.255 destination ${PORTAL_IP} 0 destination-port eq www
rule 31 permit tcp source ${VLAN_NET} 0.0.0.255 destination ${PORTAL_IP} 0 destination-port eq 443
rule 32 permit tcp source ${VLAN_NET} 0.0.0.255 destination ${PORTAL_IP} 0 destination-port eq 8080
rule 40 permit icmp source ${VLAN_NET} 0.0.0.255 destination ${PORTAL_IP} 0
rule 50 permit udp source ${VLAN_NET} 0.0.0.255 destination ${PORTAL_IP} 0 destination-port eq ntp
rule 1100 deny ip source 192.168.${VLAN_ID}.214 0.0.0.1
rule 1101 deny ip source 192.168.${VLAN_ID}.216 0.0.0.7
rule 1102 deny ip source 192.168.${VLAN_ID}.224 0.0.0.31
rule 2000 permit ip
quit
EOF
}

CMDS="system-view
"
for VLAN_ID in $VLAN_LIST; do
  CMDS="${CMDS}$(build_acl_commands "$VLAN_ID")
"
done
CMDS="${CMDS}save force
quit
"

printf "%s" "$CMDS" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}"