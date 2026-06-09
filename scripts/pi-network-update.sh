#!/bin/sh
set -eu

VLAN_LIST="${VLAN_LIST:-}"
KEA_CONFIG_PATH="${KEA_CONFIG_PATH:-}"
PYTHON_BIN="${PYTHON_BIN:-}"
NETWORK_DIR="${NETWORK_DIR:-/etc/systemd/network}"
NETWORK_WORD="${NETWORK_WORD:-192.168}"
PORTAL_IP_BYTE="${PORTAL_IP_BYTE:-4}"

if [ -z "$VLAN_LIST" ]; then
  echo "No VLAN_LIST provided for Pi network update" >&2
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

if [ ! -d "$NETWORK_DIR" ]; then
  echo "systemd-networkd config dir not found at $NETWORK_DIR" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
else
  SUDO=""
fi

update_network_file() {
  FILE_PATH="$1"
  ADDRESS="$2"

  $SUDO "$PYTHON_BIN" - <<'PY' "$FILE_PATH" "$ADDRESS"
import sys

path = sys.argv[1]
address = sys.argv[2]

with open(path, 'r', encoding='utf-8') as handle:
  lines = handle.read().splitlines()

out = []
replaced = False
for line in lines:
  if line.strip().startswith('Address='):
    out.append(f'Address={address}')
    replaced = True
  else:
    out.append(line)

if not replaced:
  inserted = False
  for idx, line in enumerate(out):
    if line.strip() == '[Network]':
      out.insert(idx + 1, f'Address={address}')
      inserted = True
      break
  if not inserted:
    out.append('[Network]')
    out.append(f'Address={address}')

with open(path, 'w', encoding='utf-8') as handle:
  handle.write('\n'.join(out) + '\n')
PY
}

lookup_address() {
  VLAN_ID="$1"
  $PYTHON_BIN - <<'PY' "$KEA_CONFIG_PATH" "$VLAN_ID" "$NETWORK_WORD" "$PORTAL_IP_BYTE"
import json
import ipaddress
import sys

config_path = sys.argv[1]
vlan_id = int(sys.argv[2])
network_word = sys.argv[3]
portal_ip_byte = sys.argv[4]

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
preferred = ipaddress.IPv4Address(f"{network_word}.{vlan_id}.{portal_ip_byte}")
if preferred in network:
  address = preferred
else:
  address = ipaddress.IPv4Address(int(network.network_address) + 4)

print(f"ADDRESS={address}/{network.prefixlen}")
PY
}

for VLAN_ID in $VLAN_LIST; do
  PY_OUT=$(lookup_address "$VLAN_ID")
  ADDRESS=$(printf '%s\n' "$PY_OUT" | awk -F= '/^ADDRESS=/{print $2}')
  if [ -z "$ADDRESS" ]; then
    echo "Failed to compute Address for VLAN $VLAN_ID" >&2
    exit 1
  fi

  FILE_PATH=$(ls -1 "$NETWORK_DIR"/*-eth0."${VLAN_ID}".network 2>/dev/null | head -n 1 || true)
  if [ -z "$FILE_PATH" ]; then
    echo "No systemd-networkd file found for VLAN $VLAN_ID" >&2
    exit 1
  fi

  update_network_file "$FILE_PATH" "$ADDRESS"
  echo "Updated $FILE_PATH to Address=$ADDRESS"

  if command -v ip >/dev/null 2>&1; then
    for existing in $($SUDO ip -4 addr show dev "eth0.${VLAN_ID}" | awk '/inet /{print $2}'); do
      $SUDO ip addr del "$existing" dev "eth0.${VLAN_ID}" >/dev/null 2>&1 || true
    done
    $SUDO ip addr add "$ADDRESS" dev "eth0.${VLAN_ID}" >/dev/null 2>&1 || true
  fi

  if command -v networkctl >/dev/null 2>&1; then
    $SUDO networkctl reconfigure "eth0.${VLAN_ID}" >/dev/null 2>&1 || true
  fi
done

if command -v systemctl >/dev/null 2>&1; then
  $SUDO systemctl restart systemd-networkd >/dev/null 2>&1 || true
fi
