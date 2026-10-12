#!/bin/sh
set -e

if [ "${ORACLE_VPS_ENABLED:-true}" = "false" ]; then
    echo "tunnel: disabled (ORACLE_VPS_ENABLED=false)"
    exec sleep infinity
fi

if [ -z "${ORACLE_VPS_HOST:-}" ]; then
    echo "tunnel: ORACLE_VPS_HOST not set — exiting"
    exit 1
fi

apk add --no-cache autossh openssh-client >/dev/null 2>&1

# A dead session is noticed in 20s (10 x 2). A connect to an unreachable
# VPS fails in 10s instead of the kernel's ~2 minute TCP timeout, then the
# loop tries again 5s later. Once the switch path is back, the tunnel is up
# within about 15s.
export AUTOSSH_GATETIME=0
export AUTOSSH_POLL=10

USER_HOST="${ORACLE_VPS_USER:-ubuntu}@${ORACLE_VPS_HOST}"
REMOTE_PORT="${ORACLE_VPS_HTTPS_PORT:-9443}"
KEY="${ORACLE_VPS_SSH_KEY_PATH:-/keys/oracle_rsa}"

while true; do
    echo "tunnel: connecting to ${USER_HOST} ..."
    autossh -M 0 -N \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=10 \
        -o ServerAliveCountMax=2 \
        -o ExitOnForwardFailure=yes \
        -o TCPKeepAlive=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$KEY" \
        -R "127.0.0.1:${REMOTE_PORT}:127.0.0.1:443" \
        "$USER_HOST" \
        || echo "tunnel: connection failed or dropped"
    echo "tunnel: retrying in 5s"
    sleep 5
done
