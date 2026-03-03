#!/bin/bash
# test-docker-agent-restart.sh
#
# Queues a job that stops and restarts the captive-portal-web container
# via the docker-agent, then watches docker-agent logs until the job completes.
#
# Usage:  bash scripts/test-docker-agent-restart.sh

set -euo pipefail

QUEUE_DIR="${QUEUE_DIR:-/home/admin/bf-network/shared/restart-queue}"
COMPOSE_DIR="/home/admin/bf-network/captive-portal"
JOB_NAME="test-restart-captive-portal-$(date +%s)"
JOB_FILE="$QUEUE_DIR/${JOB_NAME}.sh"

if [ ! -d "$QUEUE_DIR" ]; then
    echo "ERROR: Queue dir $QUEUE_DIR not found — is the stack running?"
    exit 1
fi

echo "=== Writing restart job: $JOB_NAME ==="
cat > "$JOB_FILE" <<SCRIPT
#!/bin/bash
set -uo pipefail
echo "[test] Stopping captive-portal-web..."
docker compose -f ${COMPOSE_DIR}/docker-compose.yml stop web
echo "[test] Starting captive-portal-web..."
docker compose -f ${COMPOSE_DIR}/docker-compose.yml start web
echo "[test] Done."
SCRIPT
chmod +x "$JOB_FILE"
echo "Job written to: $JOB_FILE"
echo ""
echo "=== Waiting for docker-agent to pick it up... ==="

# Poll until job is done or up to 60 seconds
DONE_FILE="$QUEUE_DIR/${JOB_NAME}.done"
LOG_FILE="$QUEUE_DIR/${JOB_NAME}.log"
for i in $(seq 1 60); do
    if [ -f "$DONE_FILE" ]; then
        echo ""
        echo "=== Job finished. Log output: ==="
        cat "$LOG_FILE"
        echo ""
        echo "=== Container status: ==="
        docker ps --format "{{.Names}}\t{{.Status}}" | grep captive-portal-web
        exit 0
    fi
    printf "."
    sleep 1
done

echo ""
echo "ERROR: Job did not complete within 60 seconds."
echo "docker-agent logs:"
docker logs docker-agent 2>&1 | tail -20
exit 1
