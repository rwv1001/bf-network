#!/bin/sh
set -eu

SWITCH_HOST="${SWITCH_HOST:?SWITCH_HOST required}"
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-/home/admin/.ssh/id_rsa}"
PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
VLAN_LIST="${VLAN_LIST:-10 20 30 40 50 60 70 80 90}"
DOH_DOT_IPS="${DOH_DOT_IPS:-1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112}"
KEA_CONFIG_PATH="${KEA_CONFIG_PATH:-}"
PYTHON_BIN="${PYTHON_BIN:-}"
BLOCK_RULE_BASE="${ACL_BLOCK_RULE_BASE:-20000}"
PERMIT_RULE_NUM="${ACL_PERMIT_RULE_NUM:-30000}"

if [ -z "$KEA_CONFIG_PATH" ]; then
  if [ -f "/kea/config/dhcp4.json" ]; then
    KEA_CONFIG_PATH="/kea/config/dhcp4.json"
  else
    KEA_CONFIG_PATH="/home/admin/bf-network/kea/config/dhcp4.json"
  fi
fi

if [ -z "$PYTHON_BIN" ]; then
  PYTHON_BIN="$(command -v python3 2>/dev/null || true)"
fi

SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

build_acl_commands() {
  VLAN_ID="$1"
  ACL_NUM=$((3000 + VLAN_ID * 10))
  PY_OUT=""
  if [ -n "$PYTHON_BIN" ] && [ -f "$KEA_CONFIG_PATH" ]; then
    PY_OUT=$($PYTHON_BIN - <<'PY' "$KEA_CONFIG_PATH" "$VLAN_ID" || true
import json
import ipaddress
import sys

config_path = sys.argv[1]
vlan_id = int(sys.argv[2])

with open(config_path, 'r', encoding='utf-8') as handle:
  data = json.load(handle)

subnet = None
for entry in data.get('Dhcp4', {}).get('subnet4', []):
  try:
    if int(entry.get('id')) == vlan_id:
      subnet = entry
      break
  except Exception:
    continue

if not subnet:
  print('ERROR=missing_subnet')
  sys.exit(1)

network = ipaddress.ip_network(subnet['subnet'], strict=False)

blocked_pool = None
for pool in subnet.get('pools', []):
  classes = pool.get('client-classes') or []
  if 'BLOCKED' in classes:
    blocked_pool = pool.get('pool')
    break

if not blocked_pool:
  block_size = 40 * (2 ** (24 - network.prefixlen))
  blocked_start = network.broadcast_address - (block_size - 1)
  blocked_pool = f"{blocked_start}-{network.broadcast_address}"

start_str, end_str = [part.strip() for part in blocked_pool.split('-', 1)]
start_ip = ipaddress.ip_address(start_str)
end_ip = ipaddress.ip_address(end_str)

print(f"VLAN_NET={network.network_address}")
print(f"VLAN_WILDCARD={network.hostmask}")
for block in ipaddress.summarize_address_range(start_ip, end_ip):
  print(f"BLOCK_RULE {block.network_address} {block.hostmask}")
PY
    )
  fi

  VLAN_NET=$(printf '%s\n' "$PY_OUT" | awk -F= '/^VLAN_NET=/{print $2}')
  VLAN_WILDCARD=$(printf '%s\n' "$PY_OUT" | awk -F= '/^VLAN_WILDCARD=/{print $2}')
  BLOCK_RULES=$(printf '%s\n' "$PY_OUT" | awk -v base="$BLOCK_RULE_BASE" 'BEGIN{rule=base} $1=="BLOCK_RULE"{printf "rule %d deny ip source %s %s\n", rule, $2, $3; rule+=10}')

  if [ -z "$VLAN_NET" ] || [ -z "$VLAN_WILDCARD" ] || [ -z "$BLOCK_RULES" ]; then
    VLAN_NET="192.168.${VLAN_ID}.0"
    VLAN_WILDCARD="0.0.0.255"
    BLOCK_RULES="rule ${BLOCK_RULE_BASE} deny ip source 192.168.${VLAN_ID}.216 0.0.0.7
  rule $((BLOCK_RULE_BASE + 10)) deny ip source 192.168.${VLAN_ID}.224 0.0.0.31
"
  fi

  DOT_DOH_RULES=""
  RULE_NUM=60
  for IP in $DOH_DOT_IPS; do
    DOT_DOH_RULES="${DOT_DOH_RULES}rule ${RULE_NUM} deny tcp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${IP} 0 destination-port eq 853
"
    RULE_NUM=$((RULE_NUM + 10))
    DOT_DOH_RULES="${DOT_DOH_RULES}rule ${RULE_NUM} deny udp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${IP} 0 destination-port eq 853
"
    RULE_NUM=$((RULE_NUM + 10))
  done

  RULE_NUM=200
  for IP in $DOH_DOT_IPS; do
    DOT_DOH_RULES="${DOT_DOH_RULES}rule ${RULE_NUM} deny tcp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${IP} 0 destination-port eq 443
"
    RULE_NUM=$((RULE_NUM + 10))
  done

  cat <<EOF
undo acl advanced ${ACL_NUM}
acl advanced ${ACL_NUM} match-order config
description "VLAN${VLAN_ID} Walled Garden and Full Access"
rule 10 permit udp source ${VLAN_NET} ${VLAN_WILDCARD} destination 255.255.255.255 0 destination-port eq bootps
rule 11 permit udp source ${VLAN_NET} ${VLAN_WILDCARD} destination 255.255.255.255 0 destination-port eq bootpc
rule 20 permit udp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${PORTAL_IP} 0 destination-port eq dns
rule 21 permit tcp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${PORTAL_IP} 0 destination-port eq dns
rule 25 deny udp source ${VLAN_NET} ${VLAN_WILDCARD} destination-port eq dns
rule 26 deny tcp source ${VLAN_NET} ${VLAN_WILDCARD} destination-port eq dns
rule 30 permit tcp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${PORTAL_IP} 0 destination-port eq www
rule 31 permit tcp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${PORTAL_IP} 0 destination-port eq 443
rule 32 permit tcp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${PORTAL_IP} 0 destination-port eq 8080
rule 40 permit icmp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${PORTAL_IP} 0
rule 50 permit udp source ${VLAN_NET} ${VLAN_WILDCARD} destination ${PORTAL_IP} 0 destination-port eq ntp
${DOT_DOH_RULES}${BLOCK_RULES}
rule ${PERMIT_RULE_NUM} permit ip
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
quit
"

printf "%s" "$CMDS" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}"