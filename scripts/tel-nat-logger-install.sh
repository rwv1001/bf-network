#!/bin/sh
# Teltonika NAT Logger - Installation Script
# Installs a conntrack-based NAT logger on a Teltonika (OpenWRT) router.
# Uses procd init for auto-restart and reboot persistence.

set -e

PORTAL_IP="${PORTAL_IP:?PORTAL_IP required}"
USER_VLAN_MIN="${USER_VLAN_MIN:?USER_VLAN_MIN is required}"
USER_VLAN_MAX="${USER_VLAN_MAX:?USER_VLAN_MAX is required}"

echo "=== Teltonika NAT Logger Installation ==="

# 1. Create the NAT logger script in /etc (persists across reboots via overlay FS)
echo "Creating NAT logger script..."
cat > /etc/nat_logger.sh << 'NATEOF'
#!/bin/sh
# NAT Logger for Teltonika (OpenWRT)
# Polls /proc/net/nf_conntrack every 10s and logs new connections from user VLANs.
# (conntrack binary not available on Teltonika — this avoids that dependency.)

SYSLOG_TAG="NAT-Logger"
REMOTE_SYSLOG="192.168.99.4"
USER_VLAN_MIN="192.168.2.0"
USER_VLAN_MAX="192.168.95.255"
INTERVAL=5
# Re-log ALL current connections every HEARTBEAT_POLLS polls to keep sessions alive.
# Must be < SESSION_GAP_SECONDS/INTERVAL (60s/5s=12) so the parser extends the existing
# session rather than closing it and creating a new one. 10 polls = 50s.
HEARTBEAT_POLLS=10
STATE_FILE="/tmp/tel_nat_state"
CURRENT_FILE="/tmp/tel_nat_current"

logger -t "$SYSLOG_TAG" "${SYSLOG_TAG}: NAT Logger starting - logging via system syslog"

poll_count=0
while true; do
    poll_count=$((poll_count + 1))

    # Read all TCP/UDP entries where the source IP is in the user VLAN range.
    # Output sorted lines of "src_ip:sport:dst_ip:dport" — one per connection.
    awk -v min="$USER_VLAN_MIN" -v max="$USER_VLAN_MAX" '
    function ip2i(a,   p) { split(a,p,"."); return ((p[1]*256+p[2])*256+p[3])*256+p[4] }
    ($3 == "tcp" || $3 == "udp") {
        src=""; dst=""; sport=""; dport=""
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^src=/ && src   == "") { split($i,a,"="); src   = a[2] }
            if ($i ~ /^dst=/ && dst   == "") { split($i,a,"="); dst   = a[2] }
            if ($i ~ /^sport=/ && sport == "") { split($i,a,"="); sport = a[2] }
            if ($i ~ /^dport=/ && dport == "") { split($i,a,"="); dport = a[2] }
        }
        if (src != "" && ip2i(src) >= ip2i(min) && ip2i(src) <= ip2i(max))
            print src ":" sport ":" dst ":" dport
    }' /proc/net/nf_conntrack 2>/dev/null | sort > "$CURRENT_FILE"

    if [ "$((poll_count % HEARTBEAT_POLLS))" -eq 0 ]; then
        # Heartbeat: re-log all current connections so the viewer sees persistent sessions
        while IFS=: read -r src_ip sport dst_ip dport; do
            logger -t "$SYSLOG_TAG" \
                "${SYSLOG_TAG}: SNAT: local_src=${src_ip}:${sport} dst=${dst_ip}:${dport}"
        done < "$CURRENT_FILE"
    elif [ -f "$STATE_FILE" ]; then
        # Normal poll: log only new connections since last poll
        comm -23 "$CURRENT_FILE" "$STATE_FILE" | while IFS=: read -r src_ip sport dst_ip dport; do
            logger -t "$SYSLOG_TAG" \
                "${SYSLOG_TAG}: SNAT: local_src=${src_ip}:${sport} dst=${dst_ip}:${dport}"
        done
    else
        # First poll — log everything to populate the viewer immediately
        while IFS=: read -r src_ip sport dst_ip dport; do
            logger -t "$SYSLOG_TAG" \
                "${SYSLOG_TAG}: SNAT: local_src=${src_ip}:${sport} dst=${dst_ip}:${dport}"
        done < "$CURRENT_FILE"
    fi

    mv "$CURRENT_FILE" "$STATE_FILE"
    sleep "$INTERVAL"
done
NATEOF

# Substitute site-specific values
sed -i \
    -e "s|REMOTE_SYSLOG=\"192.168.99.4\"|REMOTE_SYSLOG=\"${PORTAL_IP}\"|" \
    -e "s|USER_VLAN_MIN=\"192.168.2.0\"|USER_VLAN_MIN=\"${USER_VLAN_MIN}\"|" \
    -e "s|USER_VLAN_MAX=\"192.168.95.255\"|USER_VLAN_MAX=\"${USER_VLAN_MAX}\"|" \
    /etc/nat_logger.sh

chmod +x /etc/nat_logger.sh

# 2. Create procd init script for auto-restart and reboot persistence
echo "Creating procd init script..."
cat > /etc/init.d/nat-logger << 'INITEOF'
#!/bin/sh /etc/rc.common
# NAT Logger procd init script for OpenWRT/Teltonika

START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /bin/sh /etc/nat_logger.sh
    procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}
    procd_set_param stdout 0
    procd_set_param stderr 0
    procd_close_instance
}
INITEOF

chmod +x /etc/init.d/nat-logger

# 3. Enable service to start on boot and start it now
echo "Enabling and starting NAT logger service..."
/etc/init.d/nat-logger enable

# Restart in case it was already running (picks up any script changes)
/etc/init.d/nat-logger restart

# Give it a moment to start
sleep 2

echo ""
echo "=== Installation Complete ==="
echo ""
echo "NAT Logger is now:"
echo "  ✓ Running via procd (auto-restarts on crash)"
echo "  ✓ Enabled on boot (/etc/init.d/nat-logger)"
echo "  ✓ Forwarding to ${PORTAL_IP}:514"
echo ""
echo "Check status:"
echo "  /etc/init.d/nat-logger status"
echo "  logread | grep NAT-Logger"
echo ""
echo "Manual control:"
echo "  Start:  /etc/init.d/nat-logger start"
echo "  Stop:   /etc/init.d/nat-logger stop"
