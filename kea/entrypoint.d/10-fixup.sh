#!/bin/sh
set -eu

rm -f /usr/local/var/run/kea/dhcp4.kea-dhcp4.pid || true

# kea-lfc is compiled to look for its logger lockfile in /run/kea, but
# the Alpine kea package uses /usr/local/var/run/kea.  Symlink so both
# the main process and kea-lfc share the same runtime directory.
if [ ! -e /run/kea ]; then
    ln -s /usr/local/var/run/kea /run/kea
fi

mkdir -p /kea/sockets
chmod 750 /kea/sockets || true
