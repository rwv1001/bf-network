#!/bin/sh
# Start the replug queue worker daemon in the background.
# This daemon monitors /acl-queue/hp5130-replug.queue and bounces switch
# ports via SSH so that wired cross-site devices are moved to the correct VLAN.

QUEUE_SCRIPT="/scripts/hp5130-replug-queue.sh"

if [ ! -x "$QUEUE_SCRIPT" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S.000') INFO  [20-replug-queue] $QUEUE_SCRIPT not found or not executable — skipping"
    exit 0
fi

echo "$(date '+%Y-%m-%d %H:%M:%S.000') INFO  [20-replug-queue] Starting replug queue worker loop"
# The worker exits after IDLE_MAX idle cycles; wrap in a loop so it restarts.
while true; do
    "$QUEUE_SCRIPT"
    sleep 5
done &
echo "$(date '+%Y-%m-%d %H:%M:%S.000') INFO  [20-replug-queue] Replug queue worker loop started (PID $!)"
