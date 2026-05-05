#!/bin/sh
set -eu

# SWITCH_HOSTS: space-separated list of switch IPs to configure.
if [ -z "${SWITCH_HOSTS:-}" ]; then
  echo "SWITCH_HOSTS required" >&2
  exit 1
fi
SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-/home/admin/.ssh/id_rsa}"
VLAN_LIST="${VLAN_LIST:-}"
KEA_CONFIG_PATH="${KEA_CONFIG_PATH:-}"
PYTHON_BIN="${PYTHON_BIN:-}"

if [ -z "$VLAN_LIST" ]; then
  echo "No VLAN_LIST provided for interface update" >&2
  exit 1
fi

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

if [ -z "$PYTHON_BIN" ]; then
  echo "python3 not found" >&2
  exit 1
fi

if [ ! -f "$KEA_CONFIG_PATH" ]; then
  echo "Kea config not found at $KEA_CONFIG_PATH" >&2
  exit 1
fi

SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

build_interface_commands() {
  VLAN_ID="$1"
  PY_OUT=$($PYTHON_BIN - <<'PY' "$KEA_CONFIG_PATH" "$VLAN_ID"
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
router_ip = None
for option in subnet.get('option-data', []):
  if option.get('name') == 'routers' and option.get('data'):
    router_ip = option.get('data').strip()
    break

if not router_ip:
  router_ip = f"192.168.{vlan_id}.1"

print(f"ROUTER_IP={router_ip}")
print(f"NETMASK={network.netmask}")
PY
  )

  ROUTER_IP=$(printf '%s\n' "$PY_OUT" | awk -F= '/^ROUTER_IP=/{print $2}')
  NETMASK=$(printf '%s\n' "$PY_OUT" | awk -F= '/^NETMASK=/{print $2}')

  if [ -z "$ROUTER_IP" ] || [ -z "$NETMASK" ]; then
    echo "Failed to resolve router IP or netmask for VLAN $VLAN_ID" >&2
    exit 1
  fi

  # ACL number follows the pattern 3100 for VLAN 10, 3200 for VLAN 20, etc.
  ACL_NUM=$((3000 + VLAN_ID * 10))
  FILTER_DIR="inbound"

  cat <<EOF
interface Vlan-interface${VLAN_ID}
undo ip address
ip address ${ROUTER_IP} ${NETMASK}
undo packet-filter ${ACL_NUM} inbound
undo packet-filter ${ACL_NUM} outbound
undo packet-filter $((ACL_NUM + 1)) inbound
undo packet-filter $((ACL_NUM + 1)) outbound
undo packet-filter $((3000 + VLAN_ID)) inbound
undo packet-filter $((3000 + VLAN_ID)) outbound
packet-filter ${ACL_NUM} inbound
packet-filter $((ACL_NUM + 1)) outbound
quit
EOF
}

CMDS="system-view
"
for VLAN_ID in $VLAN_LIST; do
  CMDS="${CMDS}$(build_interface_commands "$VLAN_ID")
"
done
CMDS="${CMDS}save force
quit
quit
"

FAILED=0
for HOST in $SWITCH_HOSTS; do
  printf "%s" "$CMDS" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${HOST}" || FAILED=1
done
exit $FAILED
