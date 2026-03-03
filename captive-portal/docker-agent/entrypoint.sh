#!/bin/bash
# docker-agent entrypoint
# Watches QUEUE_DIR for *.sh job files, executes them one at a time.
#
# Job lifecycle:
#   <name>.sh       → picked up, renamed to .running
#   <name>.running  → executed, output written to <name>.log
#   <name>.log      → log file
#   <name>.done     → job finished (exit code appended to log)
#
# Any container can queue a job by writing a .sh file into the shared volume.
# This agent is the only container that is never restarted by jobs it runs,
# making it safe to execute 'docker compose up -d --build' for any stack.

set -uo pipefail

QUEUE_DIR="${QUEUE_DIR:-/restart-queue}"
mkdir -p "$QUEUE_DIR"

echo "[docker-agent] Started. Watching ${QUEUE_DIR} for jobs..."

while true; do
    for f in "$QUEUE_DIR"/*.sh; do
        # glob returns literal '*.sh' when no matches exist
        [ -f "$f" ] || continue

        job_name="$(basename "$f" .sh)"
        running="$QUEUE_DIR/${job_name}.running"
        logfile="$QUEUE_DIR/${job_name}.log"

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
