#!/bin/sh
# OPNsense NAT logger — persist across reboot via rc.syshook
# Emits the same NAT-Logger lines as the UDM script so nat-parser needs no new regex.
set -e

PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
USER_VLAN_MIN="${USER_VLAN_MIN:?USER_VLAN_MIN is required}"
USER_VLAN_MAX="${USER_VLAN_MAX:?USER_VLAN_MAX is required}"

echo "=== OPNsense NAT Logger Installation ==="

mkdir -p /root /usr/local/etc/rc.syshook.d/start

cat > /root/nat_logger.sh << 'NATEOF'
#!/bin/sh
# Poll pf state table; log new user-VLAN SNAT mappings to the Pi.
SYSLOG_TAG="NAT-Logger"
REMOTE_SYSLOG="__PORTAL_IP__"
USER_VLAN_MIN="__USER_VLAN_MIN__"
USER_VLAN_MAX="__USER_VLAN_MAX__"
STATE_FILE="/tmp/opnsense_nat_state"
PIDFILE="/var/run/nat_logger.pid"

echo $$ > "$PIDFILE"
touch "$STATE_FILE"

logger -t "$SYSLOG_TAG" "NAT Logger starting - logging to $REMOTE_SYSLOG"

send_log() {
    msg="$1"
    # FreeBSD logger: -h = remote host. Fall back to UDP 514.
    if logger -t "$SYSLOG_TAG" -h "$REMOTE_SYSLOG" "$msg" 2>/dev/null; then
        return 0
    fi
    printf '<14>%s %s: %s\n' "$(date '+%b %e %H:%M:%S')" "$SYSLOG_TAG" "$msg" \
        | nc -u -w1 "$REMOTE_SYSLOG" 514 2>/dev/null || true
}

send_log "NAT Logger starting"

ip_in_range() {
    awk -v ip="$1" -v min="$2" -v max="$3" '
        function ip2i(a, p) {
            split(a, p, ".")
            return ((p[1]*256 + p[2])*256 + p[3])*256 + p[4]
        }
        BEGIN { exit !(ip2i(ip) >= ip2i(min) && ip2i(ip) <= ip2i(max)) }
    ' </dev/null
}

# pfctl -s state lines look like:
#   igc0 tcp 10.7.11.6:53122 -> 142.251.154.119:443  ESTABLISHED:ESTABLISHED
# NAT form (parens = translated addr):
#   igc0 tcp 10.7.11.6:53122 (203.0.113.10:41815) -> 8.8.8.8:443  ESTABLISHED:ESTABLISHED
parse_and_log() {
    pfctl -s state 2>/dev/null | awk '
        /tcp|udp/ {
            proto = ""
            src = ""; sport = ""; dst = ""; dport = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "tcp" || $i == "udp") proto = $i
                if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/ && src == "") {
                    split($i, a, ":"); src = a[1]; sport = a[2]
                    continue
                }
                if ($i == "->" && (i+1) <= NF && $(i+1) ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/) {
                    split($(i+1), b, ":"); dst = b[1]; dport = b[2]
                }
            }
            if (src != "" && sport != "" && dst != "" && dport != "")
                print src, sport, dst, dport
        }
    ' | while read -r src_ip sport dst_ip dport; do
        [ -n "$src_ip" ] || continue
        if ! ip_in_range "$src_ip" "$USER_VLAN_MIN" "$USER_VLAN_MAX"; then
            continue
        fi
        conn_id="${src_ip}:${sport}:${dst_ip}:${dport}"
        if grep -q "^${conn_id}$" "$STATE_FILE" 2>/dev/null; then
            continue
        fi
        echo "$conn_id" >> "$STATE_FILE"
        send_log "SNAT: local_src=${src_ip}:${sport} dst=${dst_ip}:${dport}"
    done

    if [ -f "$STATE_FILE" ]; then
        lines=$(wc -l < "$STATE_FILE")
        if [ "$lines" -gt 10000 ]; then
            tail -5000 "$STATE_FILE" > "${STATE_FILE}.tmp"
            mv "${STATE_FILE}.tmp" "$STATE_FILE"
        fi
    fi
}

send_log "NAT Logger running"
while true; do
    parse_and_log
    sleep 2
done
NATEOF

sed -i.bak \
    -e "s|__PORTAL_IP__|${PORTAL_IP}|g" \
    -e "s|__USER_VLAN_MIN__|${USER_VLAN_MIN}|g" \
    -e "s|__USER_VLAN_MAX__|${USER_VLAN_MAX}|g" \
    /root/nat_logger.sh
rm -f /root/nat_logger.sh.bak
chmod 755 /root/nat_logger.sh

cat > /usr/local/etc/rc.syshook.d/start/99-natlogger << 'BOOTEOF'
#!/bin/sh
SCRIPT="/root/nat_logger.sh"
PIDFILE="/var/run/nat_logger.pid"
if [ -f "$PIDFILE" ]; then
    old=$(cat "$PIDFILE")
    kill "$old" 2>/dev/null || true
    rm -f "$PIDFILE"
fi
pkill -f "/root/nat_logger.sh" 2>/dev/null || true
sleep 1
daemon -p "$PIDFILE" "$SCRIPT"
BOOTEOF
chmod 755 /usr/local/etc/rc.syshook.d/start/99-natlogger

/usr/local/etc/rc.syshook.d/start/99-natlogger

echo "=== Installation complete ==="
echo "  script:  /root/nat_logger.sh"
echo "  boot:    /usr/local/etc/rc.syshook.d/start/99-natlogger"
echo "  target:  ${PORTAL_IP}:514"
echo "  status:  pgrep -fl nat_logger"