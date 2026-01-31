#!/bin/sh
# Manage unregistered lease tracking and cleanup

ACTION="$1"
MAC_ADDRESS="$2"
IP_ADDRESS="$3"
LEASE_SECONDS="$4"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-captive_portal}"
DB_USER="${DB_USER:-portal_user}"
DB_PASSWORD="${DB_PASSWORD:-your_secure_database_password_here}"

export PGPASSWORD="$DB_PASSWORD"
PSQL="psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -A"

is_blocked_pool_ip() {
    ip="$1"
    [ -z "$ip" ] && return 1

    old_ifs=$IFS
    IFS=.
    set -- $ip
    IFS=$old_ifs

    [ $# -ne 4 ] && return 1

    for oct in "$1" "$2" "$3" "$4"; do
        case "$oct" in
            ''|*[!0-9]* ) return 1 ;;
        esac
    done

    [ "$1" -eq 192 ] || return 1
    [ "$2" -eq 168 ] || return 1

    case "$3" in
        10|20|30|40|50|60|70|90) ;;
        *) return 1 ;;
    esac

    if [ "$4" -ge 214 ] && [ "$4" -le 254 ]; then
        return 0
    fi

    return 1
}

cleanup_expired() {
    rows=$(echo "SELECT mac_address, ip_address FROM unregistered_leases WHERE expires_at <= NOW();" | $PSQL)
    if [ -z "$rows" ]; then
        return 0
    fi

    echo "$rows" | while IFS='|' read -r mac ip; do
        [ -z "$mac" ] && continue
        if [ -n "$ip" ] && ! is_blocked_pool_ip "$ip"; then
            (/scripts/dns-hijack.sh unhijack "$ip" >/dev/null 2>&1 &) 
            (/scripts/hp5130-acl.sh unblock "$ip" >/dev/null 2>&1 &) 
        fi
        echo "DELETE FROM unregistered_leases WHERE mac_address='"$mac"';" | $PSQL >/dev/null 2>&1
    done
}

case "$ACTION" in
    cleanup)
        cleanup_expired
        exit 0
        ;;
    upsert)
        if [ -z "$MAC_ADDRESS" ] || [ -z "$IP_ADDRESS" ] || [ -z "$LEASE_SECONDS" ]; then
            echo "Usage: $0 upsert <mac> <ip> <lease_seconds>" >&2
            exit 1
        fi

        cleanup_expired

        existing_ip=$(echo "SELECT ip_address FROM unregistered_leases WHERE mac_address='"$MAC_ADDRESS"'" | $PSQL)
        if [ -n "$existing_ip" ] && [ "$existing_ip" != "$IP_ADDRESS" ]; then
            if ! is_blocked_pool_ip "$existing_ip"; then
                /scripts/dns-hijack.sh unhijack "$existing_ip" >/dev/null 2>&1
                /scripts/hp5130-acl.sh unblock "$existing_ip" >/dev/null 2>&1
            fi
        fi

        echo "INSERT INTO unregistered_leases (mac_address, ip_address, expires_at) VALUES ('"$MAC_ADDRESS"', '"$IP_ADDRESS"', NOW() + ("$LEASE_SECONDS" || ' seconds')::interval) ON CONFLICT (mac_address) DO UPDATE SET ip_address=EXCLUDED.ip_address, expires_at=EXCLUDED.expires_at, updated_at=NOW();" | $PSQL >/dev/null 2>&1

        if ! is_blocked_pool_ip "$IP_ADDRESS"; then
            (/scripts/hp5130-acl.sh block "$IP_ADDRESS" >/dev/null 2>&1 &)
            (/scripts/dns-hijack.sh hijack "$IP_ADDRESS" >/dev/null 2>&1 &)
        fi
        exit 0
        ;;
    remove|expire)
        if [ -z "$MAC_ADDRESS" ]; then
            echo "Usage: $0 $ACTION <mac> [ip]" >&2
            exit 1
        fi

        if [ -n "$IP_ADDRESS" ] && ! is_blocked_pool_ip "$IP_ADDRESS"; then
            (/scripts/dns-hijack.sh unhijack "$IP_ADDRESS" >/dev/null 2>&1 &)
            (/scripts/hp5130-acl.sh unblock "$IP_ADDRESS" >/dev/null 2>&1 &)
        fi

        echo "DELETE FROM unregistered_leases WHERE mac_address='"$MAC_ADDRESS"';" | $PSQL >/dev/null 2>&1
        exit 0
        ;;
    *)
        echo "Usage: $0 {cleanup|upsert|remove|expire} ..." >&2
        exit 1
        ;;
esac
