#!/bin/bash
# docker-agent entrypoint
# Watches QUEUE_DIR for *.sh job files, executes them one at a time.
#
# Security improvements:
# - Only accepts jobs with approved naming patterns (restart-* or job-*)
# - Automatically fixes ownership of the queue directory on startup
# - Better logging and rejection handling

set -uo pipefail

QUEUE_DIR="${QUEUE_DIR:-/restart-queue}"
AGENT_USER="${AGENT_USER:-1200:1200}"

mkdir -p "$QUEUE_DIR"

# Fix ownership so the agent (and job submitters) can read/write the queue
chown -R "$AGENT_USER" "$QUEUE_DIR" 2>/dev/null || true
chmod 2770 "$QUEUE_DIR" 2>/dev/null || true

echo "[docker-agent] Started as user $(id -u):$(id -g). Watching ${QUEUE_DIR} for jobs..."

while true; do
    for f in "$QUEUE_DIR"/*.sh; do
        [ -f "$f" ] || continue

        job_name="$(basename "$f" .sh)"
        running="$QUEUE_DIR/${job_name}.running"
        logfile="$QUEUE_DIR/${job_name}.log"

        # === Job Validation ===
        if [[ ! "$job_name" =~ ^restart- ]]; then
            echo "[docker-agent] REJECTED invalid job name: $job_name (must start with restart-)"
            rm -f "$f"
            continue
        fi

        # Atomic claim — if mv fails, another agent instance already took it
        mv "$f" "$running" 2>/dev/null || continue

        echo "[docker-agent] Starting job: $job_name"
        {
            echo "=== docker-agent job: $job_name started at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
            bash "$running"
            EXIT=$?
            echo "=== docker-agent job: $job_name finished at $(date -u +%Y-%m-%dT%H:%M:%SZ), exit ${EXIT} ==="
        } 2>&1 | tee "$logfile"

        EXIT_CODE=$(tail -1 "$logfile" | grep -o 'exit [0-9]*' | awk '{print $2}')
        echo "[docker-agent] Job $job_name done (exit ${EXIT_CODE:-?})"
        mv "$running" "$QUEUE_DIR/${job_name}.done"
    done
    sleep 1
done