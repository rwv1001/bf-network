#!/bin/bash
# UDM NAT Logger - Detailed conntrack monitoring
# Logs: Internal_IP:Port ↔ UDM_WAN_IP:Port mapping to syslog

UDM_WAN="192.168.68.194"     # UDM WAN interface IP
SYSLOG_SERVER="192.168.99.4" # Pi rsyslog server
STATE_FILE="/tmp/udm_nat_state"

# Initialize state file
touch "$STATE_FILE"

log_nat_entry() {
    local proto="$1"
    local int_ip="$2"
    local int_port="$3"
    local dst_ip="$4"
    local dst_port="$5"
    local wan_port="$6"
    
    # Log locally and to remote syslog
    logger -t udm-nat -p user.info \
        "[NEW] $proto: INTERNAL ${int_ip}:${int_port} ↔ WAN ${UDM_WAN}:${wan_port} → DEST ${dst_ip}:${dst_port}"
}

echo "UDM NAT Logger starting..."
echo "Monitoring NAT translations to WAN ${UDM_WAN}"
echo "Logging to ${SYSLOG_SERVER}"

while true; do
    # Read current conntrack table
    # Look for connections that have been NATted to UDM_WAN in reply tuple
    conntrack -L -p tcp -p udp 2>/dev/null | \
    awk -v wan_ip="$UDM_WAN" '
    /^tcp/ || /^udp/ {
        proto = $1
        orig_src = ""
        orig_sport = ""
        orig_dst = ""
        orig_dport = ""
        reply_dst = ""
        reply_dport = ""
        
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^src=/ && orig_src == "") {
                orig_src = substr($i, 5)
            } else if ($i ~ /^sport=/ && orig_sport == "") {
                orig_sport = substr($i, 7)
            } else if ($i ~ /^dst=/ && orig_dst == "") {
                orig_dst = substr($i, 5)
            } else if ($i ~ /^dport=/ && orig_dport == "") {
                orig_dport = substr($i, 7)
            } else if ($i ~ /^src=/ && orig_src != "") {
                # This is reply src (skip it)
            } else if ($i ~ /^dst=/ && orig_dst != "") {
                reply_dst = substr($i, 5)
            } else if ($i ~ /^sport=/ && orig_sport != "") {
                # This is reply sport (skip it)
            } else if ($i ~ /^dport=/ && orig_dport != "") {
                reply_dport = substr($i, 7)
            }
        }
        
        # Only log connections that got NATted to UDM WAN IP
        if (reply_dst == wan_ip && orig_src != "" && orig_sport != "" && orig_dst != "" && orig_dport != "" && reply_dport != "") {
            # Original: internal_ip:port → destination
            # Reply shows: destination → wan_ip:wan_port
            conn_id = proto ":" orig_src ":" orig_sport ":" orig_dst ":" orig_dport ":" reply_dport
            print conn_id "|" proto "|" orig_src "|" orig_sport "|" orig_dst "|" orig_dport "|" reply_dport
        }
    }
    ' | while IFS='|' read conn_id proto int_ip int_port dst_ip dst_port wan_port; do
        # Check if this is a new connection
        if ! grep -q "^$conn_id$" "$STATE_FILE" 2>/dev/null; then
            log_nat_entry "$proto" "$int_ip" "$int_port" "$dst_ip" "$dst_port" "$wan_port"
            echo "$conn_id" >> "$STATE_FILE"
        fi
    done
    
    # Cleanup state file if it gets too large (keep last 10000 entries)
    if [ -f "$STATE_FILE" ]; then
        line_count=$(wc -l < "$STATE_FILE")
        if [ "$line_count" -gt 10000 ]; then
            tail -5000 "$STATE_FILE" > "${STATE_FILE}.tmp"
            mv "${STATE_FILE}.tmp" "$STATE_FILE"
        fi
    fi
    
    sleep 2
done
