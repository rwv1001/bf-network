#!/bin/sh
set -eu

rm -f /usr/local/var/run/kea/dhcp4.kea-dhcp4.pid || true

mkdir -p /kea/sockets
chmod 750 /kea/sockets || true
