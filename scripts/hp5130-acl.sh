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

LOG_FILE="${ACL_LOG_FILE:-/var/log/hp5130-acl.log}"
timestamp() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}
log() {
  printf '%s %s\n' "$(timestamp)" "$*" >> "$LOG_FILE" 2>/dev/null || true
}

# Extract VLAN and host octet from IP (192.168.<vlan>.<host>)
VLAN_ID="$(echo "$IP_ADDRESS" | awk -F. '{print $3}')"
HOST_OCTET="$(echo "$IP_ADDRESS" | awk -F. '{print $4}')"
ACL_NUM=$((3000 + VLAN_ID * 10))
RULE_NUM=$((1000 + HOST_OCTET))

SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3"

if [ "$ACTION" = "block" ]; then
  CMDS_APPLY="system-view
acl advanced $ACL_NUM
rule $RULE_NUM deny ip source $IP_ADDRESS 0
quit
quit"
  CMDS_SAVE="save force"
elif [ "$ACTION" = "unblock" ]; then
  CMDS_APPLY="system-view
acl advanced $ACL_NUM
undo rule $RULE_NUM
quit
quit"
  CMDS_SAVE="save force"
else
  echo "Invalid action: $ACTION" >&2
  exit 1
fi

# Execute commands via SSH (force TTY for Comware)
apply_start=$(date +%s)
log "START action=$ACTION phase=apply ip=$IP_ADDRESS vlan=$VLAN_ID acl=$ACL_NUM rule=$RULE_NUM host=$SWITCH_HOST"
printf "%s\n" "$CMDS_APPLY" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}"
apply_status=$?
apply_end=$(date +%s)
apply_duration=$((apply_end - apply_start))
log "END action=$ACTION phase=apply ip=$IP_ADDRESS status=$apply_status duration_sec=$apply_duration"

save_start=$(date +%s)
log "START action=$ACTION phase=save ip=$IP_ADDRESS vlan=$VLAN_ID acl=$ACL_NUM rule=$RULE_NUM host=$SWITCH_HOST"
printf "%s\n" "$CMDS_SAVE" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}"
save_status=$?
save_end=$(date +%s)
save_duration=$((save_end - save_start))
log "END action=$ACTION phase=save ip=$IP_ADDRESS status=$save_status duration_sec=$save_duration"

exit $save_status
