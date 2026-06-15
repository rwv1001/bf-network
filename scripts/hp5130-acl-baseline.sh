#!/bin/bash
set -eu

log() { echo "[acl-baseline] $*" >&2; }

SWITCH_HOST="$(printf '%s' "${SWITCH_HOSTS:-}" | awk '{print $1}')"
[ -n "$SWITCH_HOST" ] || { echo "SWITCH_HOSTS required" >&2; exit 1; }

SWITCH_USER="${SWITCH_USER:-robert}"
SWITCH_SSH_PORT="${SWITCH_SSH_PORT:-22}"
SWITCH_KEY_PATH="${SWITCH_KEY_PATH:-/home/admin/.ssh/id_rsa}"

PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
ORACLE_VPS_HOST="${ORACLE_VPS_HOST:-}"
DOH_DOT_IPS="${DOH_DOT_IPS:-1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112}"
KEA_CONFIG_PATH="${KEA_CONFIG_PATH:-/kea/config/dhcp4.json}"
PYTHON_BIN="${PYTHON_BIN:-}"
NET="${NETWORK_WORD:-192.168}"
HIJACK_DNS_IP="${HIJACK_DNS_IP:-${NET}.99.5}"

HP5130_POLICY_PATH="${HP5130_POLICY_PATH:-${POLICY_JSON:-/scripts/scriptdata/hp5130-policy.json}}"
HP5130_CURRENT_CONFIG_PATH="${HP5130_CURRENT_CONFIG_PATH:-/scripts/scriptdata/hp5130-current-config.json}"
POLICY_JSON="$HP5130_POLICY_PATH"
WIRED_VLAN="${WIRED_VLAN:-250}"
WIRED_INBOUND_ACL="${WIRED_INBOUND_ACL:-3000}"
WIRED_OUTBOUND_ACL="${WIRED_OUTBOUND_ACL:-3999}"

ROUTER_UPLINK_ACL_MIN="${ROUTER_UPLINK_ACL_MIN:-3951}"
ROUTER_UPLINK_ACL_MAX="${ROUTER_UPLINK_ACL_MAX:-3957}"

if [ ! -f "$HP5130_POLICY_PATH" ]; then
  echo "HP5130 policy JSON not found: $HP5130_POLICY_PATH" >&2
  exit 1
fi

if [ -z "$PYTHON_BIN" ]; then
  PYTHON_BIN="$(command -v python3 2>/dev/null || true)"
fi
[ -n "$PYTHON_BIN" ] || { echo "python3 required" >&2; exit 1; }

SSH_OPTS="-i $SWITCH_KEY_PATH -p $SWITCH_SSH_PORT -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3"

CMDS="$("$PYTHON_BIN" - "$HP5130_POLICY_PATH" "$KEA_CONFIG_PATH" "$DOH_DOT_IPS" "$PORTAL_IP" "$ORACLE_VPS_HOST" "$SWITCH_HOST" "$NET" "$HIJACK_DNS_IP" "$WIRED_VLAN" "$WIRED_INBOUND_ACL" "$WIRED_OUTBOUND_ACL" "$ROUTER_UPLINK_ACL_MIN" "$ROUTER_UPLINK_ACL_MAX" "$HP5130_CURRENT_CONFIG_PATH" <<'PY'
import ipaddress
import json
import os
import re
import sys

policy_path, kea_path, doh_dot_ips, portal_ip, oracle_vps_host, switch_host, network_word, hijack_dns_ip, wired_vlan_id, wired_inbound_acl, wired_outbound_acl, router_uplink_acl_min, router_uplink_acl_max, current_config_path = sys.argv[1:15]

with open(policy_path, "r", encoding="utf-8") as fh:
    policy = json.load(fh)

routers = policy.get("routers", [])
vlans = policy.get("vlans", [])
default_router_id = policy.get("default_router_id")
network_word = policy.get("network_word", "192.168")
lan_net = ipaddress.ip_network(f"{network_word}.0.0/16", strict=False)

routers_by_id = {int(r["id"]): r for r in routers if r.get("id") is not None}

def emit(line=""):
    print(line)

def wildcard(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.hostmask), str(net.netmask)

def pbr_name(router):
    existing = router.get("pbr_name")
    if existing:
        return existing
    safe = re.sub(r"[^A-Za-z0-9]+", "-", router["name"]).strip("-").upper()
    return f"PBR-{safe}"

def nqa_name(router):
    return pbr_name(router).lower().replace("-", "").replace(" ", "_")

def router_acl(router):
    return int(router.get("uplink_acl") or (3950 + int(router["vlan_id"])))

def vlan_acl(vlan):
    return int(vlan.get("isolation_acl") or (3000 + int(vlan["vlan_id"]) * 10 + 1))

def switch_last_octet():
    try:
        return int(str(ipaddress.ip_address(switch_host)).split(".")[-1])
    except Exception:
        return 2

def switch_ip_for_subnet(cidr, fallback=None):
    if fallback:
        return fallback
    net = ipaddress.ip_network(cidr, strict=False)
    host_id = switch_last_octet()
    candidate = int(net.network_address) + host_id
    if candidate >= int(net.broadcast_address):
        candidate = int(net.network_address) + 2
    return str(ipaddress.ip_address(candidate))

def parse_visible(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [int(v) for v in value if str(v).strip()]
    return [int(v.strip()) for v in str(value).split(",") if v.strip()]

# ------------------------------------------------------------------
# Load current switch state (for cleanup)
# ------------------------------------------------------------------
existing_pbrs = set()
existing_nqas = set()

if current_config_path and os.path.isfile(current_config_path):
    try:
        with open(current_config_path, "r", encoding="utf-8") as f:
            switch_state = json.load(f)
        for host_state in switch_state.values():
            existing_pbrs.update(host_state.get("pbr_names", []))
            existing_nqas.update(host_state.get("nqa_names", []))
    except Exception as e:
        print(f"# Warning: Could not load current switch state: {e}", file=sys.stderr)

# Desired state from policy
desired_pbrs = {pbr_name(r) for r in routers}
desired_nqas = {nqa_name(r) for r in routers}
    

def load_blocked_pool_rules():
    """
    Return ACL source-deny fragments for BLOCKED pools from Kea.

    These are added to every ISP uplink ACL so blocked-pool source IPs cannot
    leave via any router.
    """
    if not kea_path or not os.path.isfile(kea_path):
        return []

    try:
        with open(kea_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return []

    subnet_by_id = {
        int(s.get("id", 0)): s
        for s in data.get("Dhcp4", {}).get("subnet4", [])
        if s.get("id") is not None
    }

    rules = []
    seen = set()

    for vlan in vlans:
        vlan_id = int(vlan["vlan_id"])
        print(f"# DEBUG vlan_id={vlan_id} wired_vlan_id={wired_vlan_id} match={vlan_id == int(wired_vlan_id)}", file=sys.stderr)

        # WIRED_VLAN is a permanent/static block case. Do not use the Kea
        # BLOCKED pool fragments for it; block the entire VLAN subnet instead.
        if vlan_id == int(wired_vlan_id):
            src, src_wc, _ = wildcard(vlan["subnet"])
            key = (src, src_wc)
            if key not in seen:
                rules.append(key)
                seen.add(key)
            continue

        subnet = subnet_by_id.get(vlan_id)
        if not subnet:
            continue

        network = ipaddress.ip_network(subnet["subnet"], strict=False)
        blocked_pool = None

        for pool in subnet.get("pools", []):
            if "BLOCKED" in (pool.get("client-classes") or []):
                blocked_pool = pool.get("pool")
                break

        if not blocked_pool:
            block_size = 40 * (2 ** max(0, 24 - network.prefixlen))
            blocked_start = network.broadcast_address - (block_size - 1)
            blocked_pool = f"{blocked_start}-{network.broadcast_address}"

        try:
            start_raw, end_raw = blocked_pool.split("-", 1)
            start_ip = ipaddress.ip_address(start_raw.strip())
            end_ip = ipaddress.ip_address(end_raw.strip())
        except Exception:
            continue

        for cidr in ipaddress.summarize_address_range(start_ip, end_ip):
            key = (str(cidr.network_address), str(cidr.hostmask))
            if key not in seen:
                rules.append(key)
                seen.add(key)

    return rules

for vlan in vlans:
    vlan["vlan_id"] = int(vlan["vlan_id"])
    vlan["resolved_isp_router_id"] = int(
        vlan.get("resolved_isp_router_id")
        or vlan.get("isp_router_id")
        or default_router_id
    )
    vlan["visible_vlans"] = parse_visible(vlan.get("visible_vlans"))

blocked_pool_sources = load_blocked_pool_rules()

emit("system-view")
# ------------------------------------------------------------------
# Cleanup old PBRs and NQAs that no longer exist in policy
# ------------------------------------------------------------------
for old_pbr in existing_pbrs:
    if old_pbr not in desired_pbrs:
        emit(f"undo policy-based-route {old_pbr}")

for old_nqa in existing_nqas:
    if old_nqa not in desired_nqas:
        emit(f"undo nqa schedule admin {old_nqa}")
        emit(f"undo nqa entry admin {old_nqa}")




# -------------------------------------------------------------------------
# Local traffic ACL for PBR deny nodes.
# Matching traffic is not policy-routed, so inter-VLAN/local traffic follows
# normal routing and then VLAN isolation ACLs decide what is allowed.
# -------------------------------------------------------------------------
emit("undo acl advanced 3001")
emit("acl advanced 3001")
emit(" description PBR-local-traffic-normal-routing")

rule = 10
for vlan in vlans:
    if int(vlan["vlan_id"]) == int(wired_vlan_id):
        continue

    src, src_wc, _ = wildcard(vlan["subnet"])
    emit(
        f" rule {rule} permit ip source {src} {src_wc} "
        f"destination {lan_net.network_address} {lan_net.hostmask}"
    )
    rule += 10

emit("quit")

# -------------------------------------------------------------------------
# PBR/NQA per ISP router.
# -------------------------------------------------------------------------
for router in routers:
    router_id = int(router["id"])
    router_vlan = int(router["vlan_id"])
    name = pbr_name(router)
    track_id = int(router.get("track_id") or router_id)
    nqa = router.get("nqa_name") or nqa_name(router)
    router_subnet = router.get("subnet") or f"{network_word}.{router_vlan}.0/24"
    router_switch_ip = switch_ip_for_subnet(router_subnet, router.get("switch_ip"))
    _, _, router_netmask = wildcard(router_subnet)

    emit(f"vlan {router_vlan}")
    emit(f" description UPLINK-TO-{router['name'].upper().replace(' ', '_')}")
    emit("quit")

    emit(f"interface Vlan-interface{router_vlan}")
    emit(f" description UPLINK-TO-{router['name'].upper().replace(' ', '_')}")
    emit(f" ip address {router_switch_ip} {router_netmask}")
    emit("quit")

    emit(f"undo policy-based-route {name}")
    emit(f"undo track {track_id}")
    emit(f"undo nqa schedule admin {nqa}")
    emit(f"undo nqa entry admin {nqa}")

    emit(f"nqa entry admin {nqa}")
    emit(" type icmp-echo")
    emit(f" destination ip {router['gateway_ip']}")
    emit(" frequency 5")
    emit(" reaction 1 checked-element probe-fail threshold-type consecutive 3 action-type trigger-only")
    emit("quit")

    emit(f"nqa schedule admin {nqa} start-time now lifetime forever")
    emit(f"track {track_id} nqa entry admin {nqa} reaction 1")

    emit(f"policy-based-route {name} deny node 5")
    emit(" if-match acl 3001")
    emit("quit")

    emit(f"policy-based-route {name} permit node 10")
    emit(f" apply next-hop {router['gateway_ip']} track {track_id}")
    emit("quit")

# -------------------------------------------------------------------------
# ISP uplink outbound ACLs.
# Each router ACL denies VLAN source subnets that are not assigned to that
# router, then blocks DoH/DoT and blocked-pool sources.
# -------------------------------------------------------------------------
for router in routers:
    router_id = int(router["id"])
    router_vlan = int(router["vlan_id"])
    acl = router_acl(router)

    emit(f"undo acl advanced {acl}")
    emit(f"acl advanced {acl}")
    emit(
        f' description "{router["name"]} Uplink Outbound - '
        f'Force PiHole + Block DoH/DoT + Block Foreign VLANs"'
    )
    emit(f" rule 5 permit ip source {portal_ip} 0")

    rule = 1000
    for vlan in vlans:
        # Skip WIRED_VLAN here — we add the full subnet in the blocked pool section instead
        if int(vlan["vlan_id"]) == int(wired_vlan_id):
            continue
        if int(vlan["resolved_isp_router_id"]) != router_id:
            src, src_wc, _ = wildcard(vlan["subnet"])
            emit(f" rule {rule} deny ip source {src} {src_wc}")
            rule += 10

    rule = 5000
    for ip in doh_dot_ips.split():
        emit(
            f" rule {rule} deny tcp source {lan_net.network_address} {lan_net.hostmask} "
            f"destination {ip} 0 destination-port eq 443"
        )
        rule += 1

    for ip in doh_dot_ips.split():
        emit(
            f" rule {rule} deny tcp source {lan_net.network_address} {lan_net.hostmask} "
            f"destination {ip} 0 destination-port eq 853"
        )
        rule += 1
        emit(
            f" rule {rule} deny udp source {lan_net.network_address} {lan_net.hostmask} "
            f"destination {ip} 0 destination-port eq 853"
        )
        rule += 1

    rule = 20000
    for src, src_wc in blocked_pool_sources:
        emit(f" rule {rule} deny ip source {src} {src_wc}")
        rule += 10

    emit(" rule 30000 permit ip")
    emit("quit")

    emit(f"interface Vlan-interface{router_vlan}")
    # Router uplink ACL numbers are reserved as 3951-3957. Clear the whole
    # range first so stale bindings, e.g. old 3953 on Vlan-interface2, cannot
    # survive after the router has moved to ACL 3952.
    for old_acl in range(int(router_uplink_acl_min), int(router_uplink_acl_max) + 1):
        emit(f" undo packet-filter {old_acl} outbound")
    emit(f" packet-filter {acl} outbound")
    emit("quit")

# -------------------------------------------------------------------------
# Per-VLAN outbound isolation ACLs + PBR binding.
# For a VLAN, every peer VLAN not listed in visible_vlans is denied.
# -------------------------------------------------------------------------
for vlan in vlans:
    target_id = int(vlan["vlan_id"])
    if target_id == int(wired_vlan_id):
        acl = wired_outbound_acl
    else:
        acl = vlan_acl(vlan)
    
    visible = set(int(v) for v in vlan.get("visible_vlans", []))

    emit(f"undo acl advanced {acl}")
    emit(f"acl advanced {acl}")
    emit(f' description "VLAN{target_id} Outbound Isolation"')

    rule = 25000
    for peer in vlans:
        peer_id = int(peer["vlan_id"])
        if peer_id == target_id:
            continue

        if peer_id not in visible:
            src, src_wc, _ = wildcard(peer["subnet"])
            emit(f" rule {rule} deny ip source {src} {src_wc}")
            rule += 10

    # === Special handling for wired_vlan_id (250) ===
    if target_id == int(wired_vlan_id):
        # Deny all ISP router uplink subnets (no internet access at all)
        for router in routers:
            rnet = router.get("subnet") or f"{network_word}.{router['vlan_id']}.0/24"
            try:
                src, src_wc, _ = wildcard(rnet)
                emit(f" rule {rule} deny ip source {src} {src_wc}")
                rule += 10
            except Exception:
                pass

    emit(" rule 30000 permit ip")
    emit("quit")

    router = routers_by_id.get(int(vlan["resolved_isp_router_id"]))
    if not router:
        raise SystemExit(
            f"VLAN {target_id} references missing ISP router "
            f"{vlan['resolved_isp_router_id']}"
        )

    vlan_switch_ip = switch_ip_for_subnet(vlan["subnet"], vlan.get("switch_ip"))
    _, _, vlan_netmask = wildcard(vlan["subnet"])

    emit(f"interface Vlan-interface{target_id}")
    emit(f" description GW_VLAN{target_id}")
    emit(f" ip address {vlan_switch_ip} {vlan_netmask}")

    if target_id == int(wired_vlan_id):
        # WIRED_VLAN is static/permanently isolated:
        # - keep/apply ACL 3000 inbound
        # - apply ACL 3999 outbound
        # - actively remove any stale PBR
        emit(f" packet-filter {wired_inbound_acl} inbound")
        emit(f" undo packet-filter {acl} inbound")
        emit(f" undo packet-filter {acl} outbound")
        emit(f" packet-filter {acl} outbound")
        emit(" undo ip policy-based-route")
    else:
        emit(f" undo packet-filter {acl} inbound")
        emit(f" undo packet-filter {acl} outbound")
        emit(f" packet-filter {acl} outbound")
        emit(" undo ip policy-based-route")
        emit(f" ip policy-based-route {pbr_name(router)}")

    
    emit("quit")

emit("undo acl advanced 3098")
emit("undo acl number 3099")
emit("acl number 3099 name VLAN99_EGRESS")
emit(f" rule 10 permit tcp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq 22")
emit(f" rule 11 permit tcp source {network_word}.0.0 0.0.255.255 destination {hijack_dns_ip} 0 destination-port eq 22")
emit(f" rule 12 permit tcp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port gt 1023")
emit(f" rule 20 permit udp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq dns")
emit(f" rule 21 permit tcp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq dns")
emit(f" rule 22 permit udp source {network_word}.0.0 0.0.255.255 destination {hijack_dns_ip} 0 destination-port eq dns")
emit(f" rule 23 permit tcp source {network_word}.0.0 0.0.255.255 destination {hijack_dns_ip} 0 destination-port eq dns")
emit(f" rule 30 permit tcp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq www")
emit(f" rule 31 permit tcp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq 443")
emit(f" rule 32 permit tcp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq 8080")
emit(f" rule 33 permit tcp source {network_word}.0.0 0.0.255.255 destination {hijack_dns_ip} 0 destination-port eq www")
emit(f" rule 34 permit tcp source {network_word}.0.0 0.0.255.255 destination {hijack_dns_ip} 0 destination-port eq 443")
emit(f" rule 35 permit tcp source {network_word}.0.0 0.0.255.255 destination {hijack_dns_ip} 0 destination-port eq 8080")
emit(f" rule 36 permit tcp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq 81")
emit(f" rule 40 permit udp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq 1812")
emit(f" rule 41 permit icmp source {network_word}.0.0 0.0.255.255 destination {hijack_dns_ip} 0")
emit(f" rule 42 permit udp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq 3799")
emit(f" rule 43 permit udp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq 1813")
emit(f" rule 50 permit icmp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0")
emit(f" rule 51 permit udp source {network_word}.0.0 0.0.255.255 destination {hijack_dns_ip} 0 destination-port eq ntp")
emit(f" rule 55 permit udp source {network_word}.0.0 0.0.255.255 destination {portal_ip} 0 destination-port eq ntp")
emit(f" rule 56 permit icmp destination {portal_ip} 0")
emit(f" rule 62 permit tcp source {portal_ip} 0 destination-port eq 443")
emit(f" rule 65 permit udp source {network_word}.1.1 0 destination {portal_ip} 0 destination-port eq syslog")
emit(f" rule 66 permit tcp source {network_word}.1.1 0 destination {portal_ip} 0 destination-port eq cmd")
emit(f" rule 71 permit tcp source 8.8.8.8 0 destination {portal_ip} 0 source-port eq 443 established")
emit(f" rule 74 permit tcp destination {portal_ip} 0 source-port eq www established")
emit(f" rule 75 permit tcp destination {portal_ip} 0 source-port eq 8080 established")
emit(f" rule 76 permit tcp source {oracle_vps_host} 0")
emit(f" rule 77 permit udp source {oracle_vps_host} 0")
emit(f" rule 78 permit tcp destination {portal_ip} 0 source-port eq 443 established")
emit(f" rule 80 permit tcp destination {portal_ip} 0 source-port eq 22 established")
emit(f" rule 83 permit udp source {portal_ip} 0 destination-port eq ntp")
emit(f" rule 84 permit udp source {hijack_dns_ip} 0 destination-port eq dns")
emit(f" rule 85 permit tcp source {hijack_dns_ip} 0 destination-port eq dns")
emit(f" rule 86 permit udp destination {portal_ip} 0 source-port eq ntp")
emit(f" rule 90 permit udp source 8.8.8.8 0 destination {portal_ip} 0 source-port eq dns")
emit(f" rule 91 permit tcp source 8.8.8.8 0 destination {portal_ip} 0 source-port eq dns established")
emit(f" rule 92 permit udp destination {portal_ip} 0 source-port gt 1023")
emit(f" rule 93 permit udp destination {hijack_dns_ip} 0 source-port gt 1023")
emit(f" rule 96 permit udp source 8.8.4.4 0 destination {portal_ip} 0 source-port eq dns")
emit(f" rule 97 permit tcp source 8.8.4.4 0 destination {portal_ip} 0 source-port eq dns established")
emit(" rule 100 deny ip")
emit("quit")
emit("interface Vlan-interface99")
emit(" undo packet-filter 3098 inbound")
emit(" undo packet-filter 3099 inbound")
emit(" undo packet-filter 3099 outbound")
emit(" packet-filter 3099 outbound")
emit("quit")

emit("save force")
emit("quit")
emit("quit")
emit("")
PY
)"

log "Using policy JSON: $HP5130_POLICY_PATH"
log "Sending ACL/PBR baseline to switch ${SWITCH_HOST}"
log "Command block:"
printf '%s\n' "$CMDS" >&2

SWITCH_OUT=$(printf '%s\n' "$CMDS" | ssh -tt $SSH_OPTS "${SWITCH_USER}@${SWITCH_HOST}" 2>&1 || true)

log "Switch output:"
printf '%s\n' "$SWITCH_OUT" >&2

if printf '%s\n' "$SWITCH_OUT" | grep -Eiq 'Invalid|Error|Incomplete|Unrecognized|Ambiguous'; then
  log "Switch reported errors while applying baseline"
  exit 1
fi

log "Done."