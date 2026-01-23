#!/bin/sh
set -eu

ACTION="${1:-}"
IP_ADDRESS="${2:-}"

if [ -z "$ACTION" ] || [ -z "$IP_ADDRESS" ]; then
  echo "Usage: $0 {block|unblock} <ip_address>" >&2
  exit 1
fi

SWITCH_HOST="${SWITCH_HOST:-192.168.1.3}"
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-/keys/id_rsa}"

# Extract VLAN and host octet from IP (192.168.<vlan>.<host>)
VLAN_ID="$(echo "$IP_ADDRESS" | awk -F. '{print $3}')"
HOST_OCTET="$(echo "$IP_ADDRESS" | awk -F. '{print $4}')"
ACL_NUM=$((3000 + VLAN_ID * 10))
RULE_NUM=$((1000 + HOST_OCTET))

SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

if [ "$ACTION" = "block" ]; then
  CMDS="system-view
acl advanced $ACL_NUM
rule $RULE_NUM deny ip source $IP_ADDRESS 0
quit
quit
save force"
elif [ "$ACTION" = "unblock" ]; then
  CMDS="system-view
acl advanced $ACL_NUM
undo rule $RULE_NUM
quit
quit
save force"
else
  echo "Invalid action: $ACTION" >&2
  exit 1
fi

# Execute commands via SSH (force TTY for Comware)
printf "%s\n" "$CMDS" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}"
