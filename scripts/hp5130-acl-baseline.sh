#!/bin/sh
set -eu

SWITCH_HOST="$(printf '%s' "${SWITCH_HOSTS:-}" | awk '{print $1}')"
[ -n "$SWITCH_HOST" ] || { echo "SWITCH_HOSTS required" >&2; exit 1; }
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-/home/admin/.ssh/id_rsa}"
PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
ORACLE_VPS_HOST="${ORACLE_VPS_HOST:?ORACLE_VPS_HOST required}"
VLAN_LIST="${VLAN_LIST:-10 20 30 40 50 60 70 80 90}"
DOH_DOT_IPS="${DOH_DOT_IPS:-1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112}"
KEA_CONFIG_PATH="${KEA_CONFIG_PATH:-}"
PYTHON_BIN="${PYTHON_BIN:-}"
BLOCK_RULE_BASE="${ACL_BLOCK_RULE_BASE:-20000}"
PERMIT_RULE_NUM="${ACL_PERMIT_RULE_NUM:-30000}"

# ACLs applied outbound on Vlan-interface1 (UDM) and Vlan-interface2 (TEL)
ACL_UDM="${ACL_UDM:-3951}"
ACL_TEL="${ACL_TEL:-3953}"

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

SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3"

# ---------------------------------------------------------------------------
# Collect blocked pool CIDRs for all VLANs from Kea config.
# Output: one line per CIDR: "rule NNNN deny ip source ADDR WILDCARD"
# ---------------------------------------------------------------------------
BLOCK_RULES=""
BLOCK_RULE_NUM="$BLOCK_RULE_BASE"

if [ -n "$PYTHON_BIN" ] && [ -f "$KEA_CONFIG_PATH" ]; then
  BLOCK_RULES=$($PYTHON_BIN - <<'PY' "$KEA_CONFIG_PATH" "$VLAN_LIST" "$BLOCK_RULE_BASE"
import json, ipaddress, sys

config_path = sys.argv[1]
vlan_ids    = [int(v) for v in sys.argv[2].split()]
rule_base   = int(sys.argv[3])

with open(config_path, 'r', encoding='utf-8') as fh:
    data = json.load(fh)

subnets = {int(s.get('id', 0)): s for s in data.get('Dhcp4', {}).get('subnet4', [])}
rule_num = rule_base
for vlan_id in vlan_ids:
    subnet = subnets.get(vlan_id)
    if not subnet:
        continue
    network = ipaddress.ip_network(subnet['subnet'], strict=False)
    blocked_pool = None
    for pool in subnet.get('pools', []):
        if 'BLOCKED' in (pool.get('client-classes') or []):
            blocked_pool = pool.get('pool')
            break
    if not blocked_pool:
        block_size   = 40 * (2 ** (24 - network.prefixlen))
        blocked_start = network.broadcast_address - (block_size - 1)
        blocked_pool  = f"{blocked_start}-{network.broadcast_address}"
    start_ip, end_ip = [ipaddress.ip_address(p.strip()) for p in blocked_pool.split('-', 1)]
    for cidr in ipaddress.summarize_address_range(start_ip, end_ip):
        print(f"rule {rule_num} deny ip source {cidr.network_address} {cidr.hostmask}")
        rule_num += 10
PY
  )
fi

# Fallback: static blocked-pool deny rules if Kea config unavailable
if [ -z "$BLOCK_RULES" ]; then
  RULE_NUM="$BLOCK_RULE_BASE"
  for VLAN_ID in $VLAN_LIST; do
    BLOCK_RULES="${BLOCK_RULES}rule ${RULE_NUM} deny ip source 192.168.${VLAN_ID}.216 0.0.0.7
rule $((RULE_NUM + 10)) deny ip source 192.168.${VLAN_ID}.224 0.0.0.31
"
    RULE_NUM=$((RULE_NUM + 20))
  done
fi

# ---------------------------------------------------------------------------
# Build DoH/DoT and PiHole rules for ACL 3951 (UDM uplink)
# ---------------------------------------------------------------------------
DOT_DOH_RULES=""
RULE_NUM=20
for IP in $DOH_DOT_IPS; do
  DOT_DOH_RULES="${DOT_DOH_RULES}rule ${RULE_NUM} deny tcp source 192.168.0.0 0.0.255.255 destination ${IP} 0 destination-port eq 443
"
  RULE_NUM=$((RULE_NUM + 1))
done
RULE_NUM=30
for IP in $DOH_DOT_IPS; do
  DOT_DOH_RULES="${DOT_DOH_RULES}rule ${RULE_NUM} deny tcp source 192.168.0.0 0.0.255.255 destination ${IP} 0 destination-port eq 853
"
  RULE_NUM=$((RULE_NUM + 1))
  DOT_DOH_RULES="${DOT_DOH_RULES}rule ${RULE_NUM} deny udp source 192.168.0.0 0.0.255.255 destination ${IP} 0 destination-port eq 853
"
  RULE_NUM=$((RULE_NUM + 1))
done

# ---------------------------------------------------------------------------
# Build DoH/DoT rules for ACL 3953 (TEL uplink) at 100+ range.
# Rules 10-50 on TEL uplink are foreign-VLAN denies, so DoH/DoT starts at 100.
# ---------------------------------------------------------------------------
TEL_DOT_DOH_RULES=""
RULE_NUM=100
for IP in $DOH_DOT_IPS; do
  TEL_DOT_DOH_RULES="${TEL_DOT_DOH_RULES}rule ${RULE_NUM} deny tcp source 192.168.0.0 0.0.255.255 destination ${IP} 0 destination-port eq 443
"
  RULE_NUM=$((RULE_NUM + 1))
done
RULE_NUM=110
for IP in $DOH_DOT_IPS; do
  TEL_DOT_DOH_RULES="${TEL_DOT_DOH_RULES}rule ${RULE_NUM} deny tcp source 192.168.0.0 0.0.255.255 destination ${IP} 0 destination-port eq 853
"
  RULE_NUM=$((RULE_NUM + 1))
  TEL_DOT_DOH_RULES="${TEL_DOT_DOH_RULES}rule ${RULE_NUM} deny udp source 192.168.0.0 0.0.255.255 destination ${IP} 0 destination-port eq 853
"
  RULE_NUM=$((RULE_NUM + 1))
done

MGMT_IP_SECONDARY="${MGMT_IP_SECONDARY:-192.168.99.5}"

CMDS="system-view
undo acl advanced ${ACL_UDM}
acl advanced ${ACL_UDM}
 description \"UDM Uplink Outbound - Force PiHole + Block DoH/DoT\"
 rule 5 permit ip source ${PORTAL_IP} 0
${DOT_DOH_RULES}${BLOCK_RULES}
 rule ${PERMIT_RULE_NUM} permit ip
quit
undo acl advanced ${ACL_TEL}
acl advanced ${ACL_TEL}
 description \"TEL Uplink Outbound - Force PiHole + Block DoH/DoT + Block Foreign VLANs\"
 rule 5 permit ip source ${PORTAL_IP} 0
 rule 10 deny ip source 192.168.8.0 0.0.3.255
 rule 20 deny ip source 192.168.20.0 0.0.0.255
 rule 30 deny ip source 192.168.30.0 0.0.0.255
 rule 40 deny ip source 192.168.48.0 0.0.3.255
 rule 50 deny ip source 192.168.68.0 0.0.3.255
${TEL_DOT_DOH_RULES}${BLOCK_RULES}
 rule ${PERMIT_RULE_NUM} permit ip
quit
undo acl advanced 3098
undo acl number 3099
acl number 3099 name VLAN99_EGRESS
 rule 10 permit tcp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq 22
 rule 11 permit tcp source 192.168.0.0 0.0.255.255 destination ${MGMT_IP_SECONDARY} 0 destination-port eq 22
 rule 12 permit tcp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port gt 1023
 rule 20 permit udp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq dns
 rule 21 permit tcp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq dns
 rule 22 permit udp source 192.168.0.0 0.0.255.255 destination ${MGMT_IP_SECONDARY} 0 destination-port eq dns
 rule 23 permit tcp source 192.168.0.0 0.0.255.255 destination ${MGMT_IP_SECONDARY} 0 destination-port eq dns
 rule 30 permit tcp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq www
 rule 31 permit tcp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq 443
 rule 32 permit tcp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq 8080
 rule 33 permit tcp source 192.168.0.0 0.0.255.255 destination ${MGMT_IP_SECONDARY} 0 destination-port eq www
 rule 34 permit tcp source 192.168.0.0 0.0.255.255 destination ${MGMT_IP_SECONDARY} 0 destination-port eq 443
 rule 35 permit tcp source 192.168.0.0 0.0.255.255 destination ${MGMT_IP_SECONDARY} 0 destination-port eq 8080
 rule 36 permit tcp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq 81
 rule 40 permit udp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq 1812
 rule 41 permit icmp source 192.168.0.0 0.0.255.255 destination ${MGMT_IP_SECONDARY} 0
 rule 42 permit udp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq 3799
 rule 43 permit udp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq 1813
 rule 50 permit icmp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0
 rule 51 permit udp source 192.168.0.0 0.0.255.255 destination ${MGMT_IP_SECONDARY} 0 destination-port eq ntp
 rule 55 permit udp source 192.168.0.0 0.0.255.255 destination ${PORTAL_IP} 0 destination-port eq ntp
 rule 56 permit icmp destination ${PORTAL_IP} 0
 rule 62 permit tcp source ${PORTAL_IP} 0 destination-port eq 443
 rule 65 permit udp source 192.168.1.1 0 destination ${PORTAL_IP} 0 destination-port eq syslog
 rule 66 permit tcp source 192.168.1.1 0 destination ${PORTAL_IP} 0 destination-port eq cmd
 rule 71 permit tcp source 8.8.8.8 0 destination ${PORTAL_IP} 0 source-port eq 443 established
 rule 74 permit tcp destination ${PORTAL_IP} 0 source-port eq www established
 rule 75 permit tcp destination ${PORTAL_IP} 0 source-port eq 8080 established
 rule 76 permit tcp source ${ORACLE_VPS_HOST} 0
 rule 77 permit udp source ${ORACLE_VPS_HOST} 0
 rule 78 permit tcp destination ${PORTAL_IP} 0 source-port eq 443 established
 rule 83 permit udp source ${PORTAL_IP} 0 destination-port eq ntp
 rule 84 permit udp source ${MGMT_IP_SECONDARY} 0 destination-port eq dns
 rule 85 permit tcp source ${MGMT_IP_SECONDARY} 0 destination-port eq dns
 rule 90 permit udp source 8.8.8.8 0 destination ${PORTAL_IP} 0 source-port eq dns
 rule 91 permit tcp source 8.8.8.8 0 destination ${PORTAL_IP} 0 source-port eq dns established
 rule 92 permit udp destination ${PORTAL_IP} 0 source-port gt 1023
 rule 93 permit udp destination ${MGMT_IP_SECONDARY} 0 source-port gt 1023
 rule 96 permit udp source 8.8.4.4 0 destination ${PORTAL_IP} 0 source-port eq dns
 rule 97 permit tcp source 8.8.4.4 0 destination ${PORTAL_IP} 0 source-port eq dns established
 rule 100 deny ip
quit
interface Vlan-interface99
 undo packet-filter 3098 inbound
 undo packet-filter 3099 inbound
 undo packet-filter 3099 outbound
 packet-filter 3099 outbound
quit
save force
quit
quit
"

# Phase 2: Remove legacy per-VLAN inbound walled-garden ACLs (3100-3900).
# These conflict with PBR. All blocking is now via 3951/3953 on uplink SVIs.
# The isolation ACLs (3x01) are outbound-only and will be rebuilt by the
# _push_vlan_isolation_acls() call in app.py after this script exits.

printf "%s" "$CMDS" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}"

build_acl_commands() {
  VLAN_ID="$1"
  ACL_NUM=$((3000 + VLAN_ID * 10))
  # Remove legacy walled-garden ACL and any stale packet-filter binding.
  # Blocking is now handled by ACL 3951/3953 on the uplink SVIs.
  cat <<EOF
interface Vlan-interface${VLAN_ID}
 undo packet-filter ${ACL_NUM} inbound
 undo packet-filter ${ACL_NUM} outbound
quit
undo acl advanced ${ACL_NUM}
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