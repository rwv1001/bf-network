#!/bin/bash
# UDM NAT Logger - Persistent Installation Script
# Survives reboots and firmware upgrades via on_boot.d

set -e

echo "=== UDM NAT Logger Persistent Installation ==="

# 1. Create the NAT logger script in /mnt/data (persists across upgrades)
echo "Creating NAT logger script..."
cat > /mnt/data/nat_logger.sh << 'NATEOF'
#!/bin/sh
# NAT Logger for UDM Pro - Logs only user VLANs (192.168.2-67, 69-95) with timestamp + local_src + dst

SYSLOG_TAG="NAT-Logger"
REMOTE_SYSLOG="192.168.99.4"

# User VLAN range (2-67, 69-95) - excludes VLAN 1 (mgmt) and VLAN 68 (Teltonika)
USER_VLAN_MIN="192.168.2.0"
USER_VLAN_MAX="192.168.95.255"

# Log startup - send to both local and remote syslog
logger -t "$SYSLOG_TAG" "NAT Logger starting - logging to $REMOTE_SYSLOG"
logger -t "$SYSLOG_TAG" -n "$REMOTE_SYSLOG" "NAT Logger starting"

conntrack -E -o extended 2>/dev/null | while read -r line; do
    # Only process TCP/UDP NEW or ESTABLISHED connections
    if ! echo "$line" | grep -qE 'tcp|udp' || ! echo "$line" | grep -qE 'NEW|ESTABLISHED'; then
        continue
    fi

    # Extract fields
    src_ip=$(echo "$line" | grep -o 'src=[0-9.]*' | cut -d= -f2 | head -1)
    dst_ip=$(echo "$line" | grep -o 'dst=[0-9.]*' | cut -d= -f2 | head -1)
    sport=$(echo "$line" | grep -o 'sport=[0-9]*' | cut -d= -f2 | head -1)
    dport=$(echo "$line" | grep -o 'dport=[0-9]*' | cut -d= -f2 | head -1)
    proto=$(echo "$line" | awk '{print $1}')

    # Skip if src_ip is not in user VLAN range (192.168.2-67, 69-95)
    # Excludes VLAN 1 (management) and VLAN 68 (Teltonika WAN)
    if ! echo "$src_ip" | grep -qE '^192\.168\.([2-9]|[1-5][0-9]|6[0-7]|69|[7-8][0-9]|9[0-5])\.'; then
        continue
    fi

    # Log to remote syslog directly (UDM syslog forwarding may not be reliable)
    logger -t "$SYSLOG_TAG" -n "$REMOTE_SYSLOG" "SNAT: local_src=${src_ip}:${sport} dst=${dst_ip}:${dport}"
done
NATEOF

chmod +x /mnt/data/nat_logger.sh

# 2. Create boot script in /mnt/data/on_boot.d/ (runs after every boot, survives upgrades)
echo "Creating boot script..."
mkdir -p /mnt/data/on_boot.d
cat > /mnt/data/on_boot.d/20-nat-logger.sh << 'BOOTEOF'
#!/bin/sh
# Auto-start NAT logger on boot (survives firmware upgrades)

SCRIPT="/mnt/data/nat_logger.sh"
PIDFILE="/var/run/nat_logger.pid"

# Kill existing instance if running
if [ -f "$PIDFILE" ]; then
    old_pid=$(cat "$PIDFILE")
    if kill -0 "$old_pid" 2>/dev/null; then
        echo "Stopping existing NAT logger (PID $old_pid)"
        # Kill process group (parent and all children)
        kill -- -"$old_pid" 2>/dev/null || kill "$old_pid" 2>/dev/null || true
        # Wait for process to die
        for i in 1 2 3 4 5; do
            kill -0 "$old_pid" 2>/dev/null || break
            sleep 1
        done
        # Force kill process group if still running
        kill -9 -- -"$old_pid" 2>/dev/null || kill -9 "$old_pid" 2>/dev/null || true
    fi
    rm -f "$PIDFILE"
fi

# Kill any stray nat_logger.sh processes
pkill -f "nat_logger.sh" 2>/dev/null || true
sleep 1

# Start NAT logger in background
echo "Starting NAT logger..."
setsid "$SCRIPT" >/dev/null 2>&1 &
echo $! > "$PIDFILE"

echo "NAT logger started (PID $(cat $PIDFILE))"
BOOTEOF

chmod +x /mnt/data/on_boot.d/20-nat-logger.sh

# 3. Start the logger immediately (don't wait for reboot)
# Note: Using logger -n flag sends syslog directly to remote - no local config needed
echo "Starting NAT logger..."
/mnt/data/on_boot.d/20-nat-logger.sh

echo ""
echo "=== Installation Complete ==="
echo ""
echo "NAT Logger is now:"
echo "  ✓ Running (PID $(cat /var/run/nat_logger.pid 2>/dev/null || echo 'unknown'))"
echo "  ✓ Persistent across reboots (/mnt/data/on_boot.d/20-nat-logger.sh)"
echo "  ✓ Persistent across upgrades (/mnt/data survives)"
echo "  ✓ Forwarding to 192.168.99.4:514"
echo ""
echo "Check status:"
echo "  ps aux | grep nat_logger"
echo "  tail -f /var/log/messages | grep NAT-Logger"
echo ""
echo "Manual control:"
echo "  Start:  /mnt/data/on_boot.d/20-nat-logger.sh"
echo "  Stop:   pkill -f nat_logger.sh"
