#!/bin/sh
# Wrapper entrypoint for dnsmasq-normal.
#
# dnsmasq creates its log file with mode 660 (owner: dhcpcd, group: root),
# which prevents the dns-parser container from reading it.  We can't chmod
# before exec because dnsmasq recreates the file at startup.  Instead we
# schedule a one-shot chmod 3 seconds after startup in a background subshell,
# then exec dnsmasq so it becomes PID 1 and handles signals normally.

(sleep 3 && chmod 644 /var/log/dnsmasq-queries.log) &

exec dnsmasq "$@"
