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

echo "tunnel: connecting to ${ORACLE_VPS_USER:-ubuntu}@${ORACLE_VPS_HOST} ..."

exec autossh -M 0 -N \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i /keys/oracle_rsa \
    -R 9443:127.0.0.1:443 \
    -R 9080:127.0.0.1:80 \
    "${ORACLE_VPS_USER:-ubuntu}@${ORACLE_VPS_HOST}"
