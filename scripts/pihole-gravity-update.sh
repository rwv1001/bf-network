#!/bin/bash
# Daily Pi-Hole gravity update script.
# Runs inside the pihole container and logs to the shared log directory.
# Installed as a host cron job — survives container rebuilds.
set -euo pipefail

LOGFILE="/home/admin/bf-network/pihole/logs/pihole_updateGravity.log"

echo "=== Gravity update started: $(date) ===" >> "$LOGFILE"

if ! docker exec pihole pihole updateGravity >> "$LOGFILE" 2>&1; then
    echo "=== Gravity update FAILED: $(date) ===" >> "$LOGFILE"
    exit 1
fi

echo "=== Gravity update finished: $(date) ===" >> "$LOGFILE"
