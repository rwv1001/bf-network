#!/bin/bash
# UDM NAT Logger - Persistent Installation Script
# Emits verified SNAT tuples, translated WAN port and kernel packet counters.
set -e

PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
USER_VLAN_MIN="${USER_VLAN_MIN:?USER_VLAN_MIN is required}"
USER_VLAN_MAX="${USER_VLAN_MAX:?USER_VLAN_MAX is required}"

echo "=== UDM NAT Logger Persistent Installation ==="
echo "Creating NAT logger script..."
cat > /mnt/data/nat_logger.sh << 'NATEOF'
#!/bin/sh
# Read the two conntrack tuples. The reply tuple's destination is the SNAT
# address and port. Do not label multicast/non-NAT entries as SNAT.
SYSLOG_TAG="NAT-Logger"
REMOTE_SYSLOG="__PORTAL_IP__"
USER_VLAN_MIN="__USER_VLAN_MIN__"
USER_VLAN_MAX="__USER_VLAN_MAX__"
logger -t "$SYSLOG_TAG" "NAT Logger starting - logging to $REMOTE_SYSLOG"
logger -t "$SYSLOG_TAG" -n "$REMOTE_SYSLOG" "NAT Logger starting"

# conntrack may not have the translated reply tuple on the first NEW event;
# such events are skipped rather than manufacturing a WAN port. UPDATE and
# DESTROY can provide it. Counters (when available) are cumulative per tuple.
conntrack -E -o extended 2>/dev/null |
awk -v min="$USER_VLAN_MIN" -v max="$USER_VLAN_MAX" '
function ip2n(ip, a) {
    if (split(ip,a,".") != 4) return -1
    for (k=1;k<=4;k++) if (a[k] !~ /^[0-9]+$/ || a[k] < 0 || a[k] > 255) return -1
    return ((a[1]*256+a[2])*256+a[3])*256+a[4]
}
function within_user_vlan(ip, num) {
    num=ip2n(ip)
    return num>=0 && num>=ip2n(min) && num<=ip2n(max)
}
{
    event=""
    if ($0 ~ /\[NEW\]/) event="NEW"
    else if ($0 ~ /\[UPDATE\]/) event="UPDATE"
    else if ($0 ~ /\[DESTROY\]/) event="DESTROY"
    if (event=="") next
    # Protocol must be TCP or UDP, not just a substring elsewhere in the line.
    proto_ok=0
    for (i=1;i<=NF;i++) if ($i=="tcp" || $i=="udp") proto_ok=1
    if (!proto_ok) next

    ns=nd=nsp=ndp=np=0
    os=od=osp=odp=rs=rd=rsp=rdp=""
    po=pr=""
    for (i=1;i<=NF;i++) {
        split($i,kv,"=")
        if (kv[1]=="src") { ns++; if (ns==1) os=kv[2]; else if (ns==2) rs=kv[2] }
        if (kv[1]=="dst") { nd++; if (nd==1) od=kv[2]; else if (nd==2) rd=kv[2] }
        if (kv[1]=="sport") { nsp++; if (nsp==1) osp=kv[2]; else if (nsp==2) rsp=kv[2] }
        if (kv[1]=="dport") { ndp++; if (ndp==1) odp=kv[2]; else if (ndp==2) rdp=kv[2] }
        if (kv[1]=="packets") { np++; if (np==1) po=kv[2]; else if (np==2) pr=kv[2] }
    }
    if (ns<2 || nd<2 || nsp<2 || ndp<2 || !within_user_vlan(os)) next
    # SNAT has a changed reply destination, while reply source is the original destination.
    # Also skips multicast/mDNS and internal connections with no source translation.
    if ((rd==os && rdp==osp) || rs!=od || rd=="" || rdp=="" || rdp !~ /^[0-9]+$/) next
    if (osp !~ /^[0-9]+$/ || odp !~ /^[0-9]+$/ || rdp<1 || rdp>65535) next
    msg="SNAT: local_src=" os ":" osp " dst=" od ":" odp \
        " wan_src_port=" rdp " wan_src_ip=" rd " event=" event
    if (np>=2 && po ~ /^[0-9]+$/ && pr ~ /^[0-9]+$/)
        msg=msg " packets=" sprintf("%.0f",po+pr)
    print msg
    fflush()
}' | while IFS= read -r payload; do
    logger -t "$SYSLOG_TAG" -n "$REMOTE_SYSLOG" "$payload"
done
NATEOF

sed -i \
    -e "s|__PORTAL_IP__|${PORTAL_IP}|" \
    -e "s|__USER_VLAN_MIN__|${USER_VLAN_MIN}|" \
    -e "s|__USER_VLAN_MAX__|${USER_VLAN_MAX}|" \
    /mnt/data/nat_logger.sh
chmod +x /mnt/data/nat_logger.sh

echo "Creating boot script..."
mkdir -p /mnt/data/on_boot.d
cat > /mnt/data/on_boot.d/20-nat-logger.sh << 'BOOTEOF'
#!/bin/sh
SCRIPT="/mnt/data/nat_logger.sh"
PIDFILE="/var/run/nat_logger.pid"
if [ -f "$PIDFILE" ]; then
    old_pid=$(cat "$PIDFILE")
    if kill -0 "$old_pid" 2>/dev/null; then
        kill -- -"$old_pid" 2>/dev/null || kill "$old_pid" 2>/dev/null || true
        for i in 1 2 3 4 5; do
            kill -0 "$old_pid" 2>/dev/null || break
            sleep 1
        done
        kill -9 -- -"$old_pid" 2>/dev/null || kill -9 "$old_pid" 2>/dev/null || true
    fi
    rm -f "$PIDFILE"
fi
pkill -f "nat_logger.sh" 2>/dev/null || true
sleep 1
setsid "$SCRIPT" >/dev/null 2>&1 &
echo $! > "$PIDFILE"
echo "NAT logger started (PID $(cat "$PIDFILE"))"
BOOTEOF
chmod +x /mnt/data/on_boot.d/20-nat-logger.sh
/mnt/data/on_boot.d/20-nat-logger.sh
echo "=== Installation complete ==="
echo "NAT logger forwarding to ${PORTAL_IP}:514"
echo "View events on syslog server with grep 'NAT-Logger'"
