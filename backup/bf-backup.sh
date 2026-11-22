#!/usr/bin/env bash
# bf-backup.sh — encrypted disaster-recovery bundles for a bf-network site.
#
# Runs inside the `backup` compose service. It never writes plaintext to disk:
# everything is staged in a tmpfs (/work) and the only artefact that leaves the
# container is an OpenPGP message encrypted to the organisation's recovery
# PUBLIC key (BACKUP_PUBLIC_KEY). The matching private key is not on any site,
# so a bundle can be copied to bf-central and to every other site safely.
#
# Subcommands:
#   daemon      scheduler loop (default): nightly run, manual trigger, pulls
#   run-once    create a bundle now, replicate, prune
#   pull        only fetch other sites' / central's bundles from bf-central
#   check       validate configuration and print what would be collected
#
# What is NOT backed up, on purpose: traffic history (DNS lookups, NAT
# sessions, Pi-hole query log). See BACKUP_EXCLUDE_TABLE_DATA.

set -uo pipefail
umask 077

REPO="${BACKUP_REPO_DIR:-/repo}"
HOSTFS="${BACKUP_HOSTFS:-/hostfs}"
OUT="${BACKUP_OUT_DIR:-/backups}"
QUEUE="${BACKUP_QUEUE_DIR:-/queue}"
WORK="${BACKUP_WORK_DIR:-/work}"

BACKUP_ENABLED="${BACKUP_ENABLED:-1}"
BACKUP_TIME="${BACKUP_TIME:-02:40}"
BACKUP_KEEP_LOCAL="${BACKUP_KEEP_LOCAL:-14}"
BACKUP_KEEP_PEER="${BACKUP_KEEP_PEER:-2}"
BACKUP_REPLICATE="${BACKUP_REPLICATE:-1}"
BACKUP_PULL_INTERVAL_HOURS="${BACKUP_PULL_INTERVAL_HOURS:-6}"
BACKUP_MAX_BUNDLE_MB="${BACKUP_MAX_BUNDLE_MB:-200}"
BACKUP_EXCLUDE_TABLE_DATA="${BACKUP_EXCLUDE_TABLE_DATA:-dns_lookups dns_resolutions pihole_blocked_queries nat_sessions}"
BACKUP_FILE_UID="${BACKUP_FILE_UID:-1000}"
BACKUP_FILE_GID="${BACKUP_FILE_GID:-1000}"

NAME_RE='^bfbackup-(site|central)-[A-Za-z0-9._-]+-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.gpg$'

log()  { printf '%s [backup] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
warn() { log "WARNING: $*"; }

# Run a function in THIS shell (so the globals it sets survive) and keep what
# it printed on stdout as the error text in ERR.
ERR=""
try() {
    local rc=0
    "$@" > "$WORK/try.out" || rc=$?
    ERR="$(cat "$WORK/try.out" 2>/dev/null)"
    return $rc
}

sanitize_id() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-' | sed 's/^[.-]*//; s/-*$//'; }

site_id() {
    local id="${CENTRAL_SITE_ID:-${BACKUP_SITE_ID:-}}"
    [[ -n "$id" ]] || id="$(cat "$HOSTFS/etc/hostname" 2>/dev/null || hostname)"
    sanitize_id "$id"
}

# Read KEY from the site's .env without sourcing it (values are data, not code).
envget() {
    local key="$1" line
    line="$(grep -E "^${key}=" "$REPO/.env" 2>/dev/null | tail -n1)" || true
    line="${line#*=}"
    line="${line%$'\r'}"
    if [[ "$line" == \"*\" || "$line" == \'*\' ]]; then line="${line:1:${#line}-2}"; fi
    printf '%s' "$line"
}

git_commit() {
    local head ref
    head="$(cat "$REPO/.git/HEAD" 2>/dev/null)" || { echo unknown; return; }
    if [[ "$head" == ref:* ]]; then
        ref="${head#ref: }"
        if [[ -f "$REPO/.git/$ref" ]]; then
            cat "$REPO/.git/$ref"
        else
            awk -v r="$ref" '$2==r{print $1}' "$REPO/.git/packed-refs" 2>/dev/null | head -n1
        fi
    else
        echo "$head"
    fi
}

host_home() {
    # The repo lives in the service user's home on the host (GIT_REPO_DIR).
    local repo_host="${BACKUP_HOST_REPO_DIR:-}"
    [[ -n "$repo_host" ]] || return 1
    printf '%s%s' "$HOSTFS" "$(dirname "$repo_host")"
}

# ── Recovery key ─────────────────────────────────────────────────────────────

KEY_FILE=""
KEY_FPR=""

setup_recovery_key() {
    KEY_FILE=""; KEY_FPR=""
    local b64="${BACKUP_PUBLIC_KEY:-}"
    b64="${b64//[[:space:]]/}"
    [[ -n "$b64" ]] || { echo "BACKUP_PUBLIC_KEY is not set"; return 1; }

    mkdir -p "$WORK/gnupg" && chmod 700 "$WORK/gnupg"
    local f="$WORK/recovery.pub"
    if ! printf '%s' "$b64" | base64 -d > "$f" 2>/dev/null || [[ ! -s "$f" ]]; then
        echo "BACKUP_PUBLIC_KEY is not valid base64"; return 1
    fi
    if grep -q "PRIVATE KEY" "$f"; then
        rm -f "$f"
        echo "BACKUP_PUBLIC_KEY contains a PRIVATE key. Remove it from .env now and generate a new recovery key."
        return 1
    fi
    local colons
    colons="$(gpg --homedir "$WORK/gnupg" --batch --no-tty --with-colons --show-keys "$f" 2>/dev/null)" || {
        echo "BACKUP_PUBLIC_KEY is not an OpenPGP public key"; return 1; }
    if grep -q '^sec:' <<<"$colons"; then
        rm -f "$f"
        echo "BACKUP_PUBLIC_KEY contains a PRIVATE key. Remove it from .env now and generate a new recovery key."
        return 1
    fi
    # Field 12 holds the capabilities; need a usable encryption (sub)key.
    if ! awk -F: '($1=="pub"||$1=="sub") && $2!~/[redi]/ && $12~/e/ {ok=1} END{exit !ok}' <<<"$colons"; then
        echo "BACKUP_PUBLIC_KEY has no usable encryption key (expired or revoked?)"; return 1
    fi
    KEY_FPR="$(awk -F: '$1=="fpr"{print $10; exit}' <<<"$colons")"
    KEY_FILE="$f"
    return 0
}

encrypt_stream() {  # stdin -> $1
    gpg --homedir "$WORK/gnupg" --batch --no-tty --yes --quiet \
        --trust-model always --compress-algo none \
        --recipient-file "$KEY_FILE" --output "$1" --encrypt
}

# ── Status file (read by the admin page) ─────────────────────────────────────

STATUS_JSON='{}'
status_set() {  # key jsonvalue
    STATUS_JSON="$(jq -c --arg k "$1" --argjson v "$2" '.[$k]=$v' <<<"$STATUS_JSON")"
}
status_str() { status_set "$1" "$(jq -Rn --arg v "$2" '$v')"; }
status_load() {
    STATUS_JSON="$(jq -c . "$OUT/status.json" 2>/dev/null)" || STATUS_JSON='{}'
    [[ -n "$STATUS_JSON" ]] || STATUS_JSON='{}'
}
status_write() {
    status_str updated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%s\n' "$STATUS_JSON" > "$OUT/status.json.tmp" \
        && mv -f "$OUT/status.json.tmp" "$OUT/status.json"
    publish "$OUT/status.json"
}

publish() {  # make a path readable by the portal web user only
    chown "$BACKUP_FILE_UID:$BACKUP_FILE_GID" "$@" 2>/dev/null || true
    local p
    for p in "$@"; do
        if [[ -d "$p" ]]; then chmod 750 "$p"; else chmod 640 "$p"; fi
    done
}

prepare_dirs() {
    mkdir -p "$OUT/own" "$OUT/peers" "$OUT/central" "$WORK"
    publish "$OUT" "$OUT/own" "$OUT/peers" "$OUT/central"
    if [[ -d "$QUEUE" ]]; then
        chown "$BACKUP_FILE_UID:$BACKUP_FILE_GID" "$QUEUE" 2>/dev/null || true
        chmod 770 "$QUEUE" 2>/dev/null || true
    fi
}

# ── Collection ───────────────────────────────────────────────────────────────

STAGE=""
COLLECTED=()
MISSING=()

# collect <source path> <dest path relative to stage> [tar --exclude patterns…]
collect() {
    local src="$1" rel="$2"; shift 2
    if [[ ! -e "$src" ]]; then MISSING+=("$rel"); return 0; fi
    local dest="$STAGE/$rel" ex=() p
    for p in "$@"; do ex+=(--exclude="$p"); done
    if [[ -d "$src" ]]; then
        mkdir -p "$dest"
        if ! tar -C "$src" "${ex[@]}" --ignore-failed-read -cf - . 2>/dev/null | tar -C "$dest" -xf - 2>/dev/null; then
            warn "partial copy of $src"
        fi
    else
        mkdir -p "$(dirname "$dest")"
        cp -p "$src" "$dest" 2>/dev/null || { MISSING+=("$rel"); return 0; }
    fi
    COLLECTED+=("$rel")
}

dump_database() {
    local out="$STAGE/db/captive_portal.sql" args=() t
    mkdir -p "$STAGE/db"
    for t in $BACKUP_EXCLUDE_TABLE_DATA; do
        [[ "$t" =~ ^[A-Za-z0-9_]+$ ]] || { warn "ignoring bad table name '$t'"; continue; }
        args+=(--exclude-table-data="$t" --exclude-table-data="${t}_*")
    done
    # --clean --if-exists: the dump can be loaded over the schema that
    # init-db.sql / Kea create on a fresh server.
    if ! nice -n 19 pg_dump --clean --if-exists "${args[@]}" -f "$out" 2>"$WORK/pg_dump.err"; then
        echo "pg_dump failed: $(tail -n 3 "$WORK/pg_dump.err" | tr '\n' ' ')"
        return 1
    fi
    if ! tail -n 5 "$out" | grep -q "PostgreSQL database dump complete"; then
        echo "pg_dump output is incomplete"; return 1
    fi
    COLLECTED+=("db/captive_portal.sql")
}

collect_files() {
    local home; home="$(host_home)" || home=""

    # Repository-local state that git does not hold.
    collect "$REPO/.env"                      repo/.env
    collect "$REPO/kea/config"                repo/kea/config
    collect "$REPO/scripts/scriptdata"        repo/scripts/scriptdata
    collect "$REPO/mdns/peers.json"           repo/mdns/peers.json
    collect "$REPO/shared/ssh-known-hosts"    repo/shared/ssh-known-hosts
    collect "$REPO/npm/data"                  repo/npm/data './logs'
    collect "$REPO/npm/letsencrypt"           repo/npm/letsencrypt
    # Pi-hole: settings and lists, not the query history.
    collect "$REPO/pihole/etc-pihole"         repo/pihole/etc-pihole \
        './pihole-FTL.db*' './gravity_old.db' './gravity_backups' './config_backups' \
        './listsCache' './migration_backup' './logs' './*.log'

    # Switch start-up configurations (TFTP'd here by each switch every night).
    local f
    mkdir -p "$STAGE/switches"
    for f in "$HOSTFS"/var/lib/tftpboot/switch-backups/*.cfg "$REPO"/tftp-inbox/*.cfg; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        (( $(stat -c %s "$f") <= 2097152 )) || continue
        cp -p "$f" "$STAGE/switches/" 2>/dev/null && COLLECTED+=("switches/$(basename "$f")")
    done

    # Host configuration written by the installer.
    collect "$HOSTFS/etc/systemd/network"                         host/etc/systemd/network
    collect "$HOSTFS/etc/systemd/system/pi-ssh-via-vps.service"   host/etc/systemd/system/pi-ssh-via-vps.service
    collect "$HOSTFS/etc/docker/daemon.json"                      host/etc/docker/daemon.json
    collect "$HOSTFS/etc/hostname"                                host/etc/hostname
    collect "$HOSTFS/etc/default/tftpd-hpa"                       host/etc/default/tftpd-hpa
    collect "$HOSTFS/etc/chrony/chrony.conf"                      host/etc/chrony/chrony.conf
    for f in "$HOSTFS"/etc/cron.d/bf-network*; do
        [[ -f "$f" ]] && collect "$f" "host/etc/cron.d/$(basename "$f")"
    done
    collect "$HOSTFS/var/lib/bf-network-installer"                installer-store
    collect "$HOSTFS/root/.acme.sh"                               root/.acme.sh './*.log'
    collect "$HOSTFS/root/.bunny_api_key"                         root/.bunny_api_key

    # The service user's keys, certificates and UniFi controller set-up.
    if [[ -n "$home" && -d "$home" ]]; then
        collect "$home/.ssh"                          home/.ssh './known_hosts.old'
        collect "$home/certs"                         home/certs
        collect "$home/unifi/docker-compose.yml"      home/unifi/docker-compose.yml
        collect "$home/unifi/unifi-tunnel-entrypoint.sh" home/unifi/unifi-tunnel-entrypoint.sh
        collect "$home/unifi/data/data/backup"        home/unifi/data/data/backup
    else
        MISSING+=("home (BACKUP_HOST_REPO_DIR unset or not mounted)")
    fi
}

write_manifest() {
    local id="$1" stamp="$2" home
    home="$(dirname "${BACKUP_HOST_REPO_DIR:-/unknown/x}")"
    local tunnel_port=""
    if [[ -f "$STAGE/host/etc/systemd/system/pi-ssh-via-vps.service" ]]; then
        tunnel_port="$(grep -oE -- '-R[[:space:]]*([^:[:space:]]*:)?[0-9]+:' \
            "$STAGE/host/etc/systemd/system/pi-ssh-via-vps.service" | grep -oE '[0-9]+:$' | tr -d ':' | head -n1)"
    fi
    jq -n \
        --arg kind site --arg site_id "$id" --arg created "$stamp" \
        --arg hostname "$(cat "$HOSTFS/etc/hostname" 2>/dev/null)" \
        --arg commit "$(git_commit)" --arg fpr "$KEY_FPR" \
        --arg repo_dir "${BACKUP_HOST_REPO_DIR:-}" --arg home "$home" \
        --arg excluded "$BACKUP_EXCLUDE_TABLE_DATA" \
        --arg portal_url "$(envget PORTAL_URL)" \
        --arg central_url "$(envget CENTRAL_API_URL)" \
        --arg vps_host "$(envget ORACLE_VPS_HOST)" --arg vps_user "$(envget ORACLE_VPS_USER)" \
        --arg vps_https "$(envget ORACLE_VPS_HTTPS_PORT)" --arg vps_ssh "$tunnel_port" \
        --arg vps_key "$(envget ORACLE_VPS_SSH_KEY_PATH)" \
        --arg fwd_host "$(envget PORTAL_FORWARD_HOST)" --arg fwd_port "$(envget PORTAL_FORWARD_PORT)" \
        --arg unifi_port "$(envget UNIFI_FORWARD_PORT)" \
        --arg switches "$(envget SWITCH_HOSTS)" \
        --argjson collected "$(printf '%s\n' "${COLLECTED[@]}" | jq -R . | jq -s .)" \
        --argjson missing "$(printf '%s\n' "${MISSING[@]:-}" | jq -R 'select(length>0)' | jq -s .)" \
        '{format: 1, kind: $kind, site_id: $site_id, created_utc: $created,
          hostname: $hostname, git_commit: $commit, recovery_key_fingerprint: $fpr,
          host: {repo_dir: $repo_dir, home: $home},
          portal_url: $portal_url, central_api_url: $central_url, switch_hosts: $switches,
          database: {file: "db/captive_portal.sql", format: "pg_dump plain, --clean --if-exists",
                     table_data_excluded: ($excluded | split(" ") | map(select(length>0)))},
          tunnel_vps: {host: $vps_host, user: $vps_user, https_port: $vps_https,
                       admin_ssh_tunnel_port: $vps_ssh, ssh_key_path: $vps_key,
                       portal_forward_host: $fwd_host, portal_forward_port: $fwd_port,
                       unifi_forward_port: $unifi_port},
          collected: $collected, missing: $missing}' > "$STAGE/manifest.json"
}

# ── Bundle creation ──────────────────────────────────────────────────────────

LAST_BUNDLE=""

create_bundle() {
    local id stamp name tmp err
    id="$(site_id)"
    [[ -n "$id" ]] || { echo "cannot determine a site id (set CENTRAL_SITE_ID)"; return 1; }
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    name="bfbackup-site-${id}-${stamp}.tar.gz.gpg"
    STAGE="$WORK/stage"; COLLECTED=(); MISSING=()
    rm -rf "$STAGE"; mkdir -p "$STAGE"

    dump_database || { rm -rf "$STAGE"; return 1; }
    collect_files
    [[ -f "$STAGE/repo/.env" ]] || { echo ".env not readable at $REPO/.env"; rm -rf "$STAGE"; return 1; }
    write_manifest "$id" "$stamp" || { echo "manifest generation failed"; rm -rf "$STAGE"; return 1; }

    tmp="$OUT/own/.$name.partial"
    if ! nice -n 19 tar -C "$STAGE" -cf - . | nice -n 19 gzip -6 | encrypt_stream "$tmp"; then
        rm -f "$tmp"; rm -rf "$STAGE"
        echo "encryption failed"; return 1
    fi
    rm -rf "$STAGE"
    # A public-key encrypted OpenPGP message starts with a PKESK packet.
    local first; first="$(head -c1 "$tmp" | od -An -tu1 | tr -d ' ')"
    case "$first" in 132|133|193) ;; *) rm -f "$tmp"; echo "unexpected output format (byte $first)"; return 1 ;; esac
    mv -f "$tmp" "$OUT/own/$name"
    publish "$OUT/own/$name"
    LAST_BUNDLE="$OUT/own/$name"
    return 0
}

prune_dir() {  # dir keep
    local dir="$1" keep="$2"
    [[ -d "$dir" && "$keep" =~ ^[0-9]+$ && "$keep" -ge 1 ]] || return 0
    ls -1 "$dir" 2>/dev/null | grep -E "$NAME_RE" | sort -r | tail -n +"$((keep + 1))" | while read -r f; do
        rm -f "$dir/$f" && log "pruned $(basename "$dir")/$f"
    done
    rm -f "$dir"/.*.partial 2>/dev/null || true
}

# ── Replication through bf-central ───────────────────────────────────────────

central_enabled() {
    [[ "$BACKUP_REPLICATE" == "1" && -n "${CENTRAL_API_URL:-}" && -n "${CENTRAL_API_KEY:-}" ]]
}

CURL_CODE="000"
central_curl() {  # method path [curl args…]  -> body in $WORK/curl.body, HTTP code in CURL_CODE
    local method="$1" path="$2"; shift 2
    : > "$WORK/curl.body"
    CURL_CODE="$(curl -sS -X "$method" --connect-timeout 15 --max-time 900 \
        -H "X-API-Key: ${CENTRAL_API_KEY}" -o "$WORK/curl.body" -w '%{http_code}' \
        "$@" "${CENTRAL_API_URL%/}$path" 2>"$WORK/curl.err")" || CURL_CODE="000"
}

upload_bundle() {
    local file="$1" name sha size
    name="$(basename "$file")"
    size="$(stat -c %s "$file")"
    if (( size > BACKUP_MAX_BUNDLE_MB * 1024 * 1024 )); then
        echo "bundle is $((size / 1048576)) MB, over BACKUP_MAX_BUNDLE_MB=$BACKUP_MAX_BUNDLE_MB; not uploaded"
        return 1
    fi
    sha="$(sha256sum "$file" | cut -d' ' -f1)"
    central_curl PUT "/api/v1/backup/site/$name" \
        -H "Content-Type: application/octet-stream" -H "X-Backup-SHA256: $sha" \
        --data-binary "@$file"
    if [[ "$CURL_CODE" != "200" && "$CURL_CODE" != "201" ]]; then
        echo "upload failed: HTTP $CURL_CODE $(head -c 200 "$WORK/curl.body") $(head -c 200 "$WORK/curl.err" 2>/dev/null)"
        return 1
    fi
    return 0
}

PULLED=0
pull_bundles() {
    local me index
    me="$(site_id)"; PULLED=0
    central_curl GET /api/v1/backup/index
    if [[ "$CURL_CODE" != "200" ]]; then
        echo "index failed: HTTP $CURL_CODE $(head -c 200 "$WORK/curl.body") $(head -c 200 "$WORK/curl.err" 2>/dev/null)"; return 1
    fi
    index="$(cat "$WORK/curl.body")"
    # newest BACKUP_KEEP_PEER per (kind, owner), excluding our own site bundles
    local wanted
    wanted="$(jq -r --arg me "$me" --argjson keep "$BACKUP_KEEP_PEER" '
        [.backups[]? | select(.kind=="central" or .site_id != $me)]
        | group_by(.kind + "/" + .site_id)
        | map(sort_by(.filename) | reverse | .[:$keep]) | flatten
        | .[] | [.kind, .site_id, .filename, .sha256, (.size|tostring)] | @tsv' <<<"$index" 2>/dev/null)" || {
        echo "index was not valid JSON"; return 1; }

    local kind owner name sha size dir tmp got rc=0
    declare -A keepset=()
    while IFS=$'\t' read -r kind owner name sha size; do
        [[ -n "$name" ]] || continue
        [[ "$name" =~ $NAME_RE && "$owner" =~ ^[A-Za-z0-9._-]+$ && "$owner" != "." && "$owner" != ".." ]] || {
            warn "ignoring index entry with unsafe name: $kind/$owner/$name"; continue; }
        [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { warn "ignoring $name: no checksum"; continue; }
        if [[ "$kind" == "central" ]]; then dir="$OUT/central"; else dir="$OUT/peers/$owner"; fi
        keepset["$dir/$name"]=1
        [[ -f "$dir/$name" ]] && continue
        mkdir -p "$dir"; publish "$dir"
        tmp="$dir/.$name.partial"
        CURL_CODE="$(curl -sS --connect-timeout 15 --max-time 900 -H "X-API-Key: ${CENTRAL_API_KEY}" \
            -o "$tmp" -w '%{http_code}' "${CENTRAL_API_URL%/}/api/v1/backup/file/$kind/$owner/$name" \
            2>"$WORK/curl.err")" || CURL_CODE="000"
        if [[ "$CURL_CODE" != "200" ]]; then
            rm -f "$tmp"; warn "download of $name failed: HTTP $CURL_CODE"; rc=1; continue
        fi
        got="$(sha256sum "$tmp" | cut -d' ' -f1)"
        if [[ "$got" != "$sha" ]]; then
            rm -f "$tmp"; warn "checksum mismatch for $name; discarded"; rc=1; continue
        fi
        mv -f "$tmp" "$dir/$name"; publish "$dir/$name"
        PULLED=$((PULLED + 1))
        log "pulled $kind/$owner/$name ($size bytes)"
    done <<<"$wanted"

    # Drop copies that central no longer lists among the newest, but never
    # delete everything for an owner just because an index came back empty.
    local d f
    for d in "$OUT/central" "$OUT"/peers/*/; do
        [[ -d "$d" ]] || continue
        d="${d%/}"
        local any=0
        for f in "$d"/bfbackup-*.gpg; do [[ -n "${keepset[$f]:-}" ]] && any=1; done
        (( any )) || continue
        for f in "$d"/bfbackup-*.gpg; do
            [[ -f "$f" && -z "${keepset[$f]:-}" ]] && rm -f "$f" && log "pruned ${f#"$OUT"/}"
        done
    done
    [[ $rc -eq 0 ]] || { echo "some downloads failed"; return 1; }
    return 0
}

# ── Runs ─────────────────────────────────────────────────────────────────────

run_pull() {
    central_enabled || return 0
    status_load
    if try pull_bundles; then
        status_set last_pull "$(jq -n --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson n "$PULLED" '{utc:$t, ok:true, new:$n}')"
    else
        warn "pull: $ERR"
        status_set last_pull "$(jq -n --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg e "$ERR" '{utc:$t, ok:false, error:$e}')"
    fi
    status_write
}

run_once() {
    local reason="${1:-manual}" err now
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    prepare_dirs
    status_load
    status_str site_id "$(site_id)"

    if [[ "$BACKUP_ENABLED" != "1" ]]; then
        status_str state disabled; status_str detail "BACKUP_ENABLED is not 1"; status_write
        log "disabled (BACKUP_ENABLED=$BACKUP_ENABLED)"; return 0
    fi
    if ! try setup_recovery_key; then
        status_str state unconfigured; status_str detail "$ERR"; status_str key_fingerprint ""; status_write
        warn "$ERR — no backup written. Generate a recovery key with the installer (--init-recovery-key) and put the public part in .env as BACKUP_PUBLIC_KEY."
        return 1
    fi
    status_str key_fingerprint "$KEY_FPR"

    log "starting $reason backup for site $(site_id)"
    if ! try create_bundle; then
        warn "backup failed: $ERR"
        status_str state error; status_str detail "$ERR"
        status_set last_run "$(jq -n --arg t "$now" --arg r "$reason" --arg e "$ERR" '{utc:$t, reason:$r, ok:false, error:$e}')"
        status_write; return 1
    fi
    local name size sha
    name="$(basename "$LAST_BUNDLE")"; size="$(stat -c %s "$LAST_BUNDLE")"
    sha="$(sha256sum "$LAST_BUNDLE" | cut -d' ' -f1)"
    log "wrote own/$name ($size bytes)"
    status_str state ok; status_str detail ""
    status_set last_run "$(jq -n --arg t "$now" --arg r "$reason" --arg n "$name" --arg s "$sha" --argjson z "$size" \
        '{utc:$t, reason:$r, ok:true, filename:$n, size:$z, sha256:$s}')"
    prune_dir "$OUT/own" "$BACKUP_KEEP_LOCAL"

    if central_enabled; then
        [[ "${CENTRAL_API_URL}" == https://* ]] || status_str transport_warning \
            "CENTRAL_API_URL is not https: the bundle is encrypted, but the site API key crosses the network in clear text."
        [[ "${CENTRAL_API_URL}" == https://* ]] && status_str transport_warning ""
        if try upload_bundle "$LAST_BUNDLE"; then
            log "uploaded $name to central"
            status_set last_upload "$(jq -n --arg t "$now" --arg n "$name" '{utc:$t, ok:true, filename:$n}')"
        else
            warn "$ERR"
            status_set last_upload "$(jq -n --arg t "$now" --arg e "$ERR" '{utc:$t, ok:false, error:$e}')"
        fi
        status_write
        run_pull
    else
        status_set last_upload '{"ok":false,"error":"replication off (CENTRAL_API_URL/CENTRAL_API_KEY unset or BACKUP_REPLICATE=0): this bundle exists only on this server"}'
        status_write
    fi
    return 0
}

cmd_check() {
    prepare_dirs
    echo "site id          : $(site_id)"
    echo "git commit       : $(git_commit)"
    echo "host home        : $(host_home || echo '(unknown: BACKUP_HOST_REPO_DIR unset)')"
    if try setup_recovery_key; then echo "recovery key     : $KEY_FPR"
    else echo "recovery key     : NOT USABLE — $ERR"; fi
    if pg_isready -q -t 5; then echo "database         : reachable"; else echo "database         : NOT reachable"; fi
    echo "tables w/o data  : $BACKUP_EXCLUDE_TABLE_DATA"
    if central_enabled; then echo "replication      : ${CENTRAL_API_URL}"; else echo "replication      : off"; fi
    echo "schedule         : daily at $BACKUP_TIME (container local time), keep $BACKUP_KEEP_LOCAL"
}

cmd_daemon() {
    prepare_dirs
    renice -n 19 $$ >/dev/null 2>&1 || true
    ionice -c3 -p $$ >/dev/null 2>&1 || true
    [[ "$BACKUP_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || { warn "BACKUP_TIME '$BACKUP_TIME' is not HH:MM; using 02:40"; BACKUP_TIME="02:40"; }
    log "scheduler started: daily at $BACKUP_TIME, keep $BACKUP_KEEP_LOCAL local / $BACKUP_KEEP_PEER per peer"

    # Publish the configuration state straight away so the admin page is useful
    # before the first run.
    status_load; status_str site_id "$(site_id)"
    if [[ "$BACKUP_ENABLED" != "1" ]]; then status_str state disabled; status_str detail "BACKUP_ENABLED is not 1"
    elif try setup_recovery_key; then
        status_str key_fingerprint "$KEY_FPR"
        [[ "$(jq -r '.state // ""' <<<"$STATUS_JSON")" =~ ^(ok|error)$ ]] || { status_str state waiting; status_str detail "no backup has run yet"; }
    else status_str state unconfigured; status_str detail "$ERR"; status_str key_fingerprint ""; warn "$ERR"; fi
    status_str schedule "$BACKUP_TIME"
    status_write

    local last_day last_pull=0 today now_hm now_s
    last_day="$(cat "$OUT/.last-scheduled-day" 2>/dev/null || true)"
    while true; do
        if [[ -e "$QUEUE/trigger" ]]; then
            rm -f "$QUEUE/trigger"
            run_once manual || true
            last_pull="$(date +%s)"
        fi
        today="$(date +%F)"; now_hm="$(date +%H:%M)"
        if [[ "$today" != "$last_day" && ! "$now_hm" < "$BACKUP_TIME" ]]; then
            last_day="$today"; printf '%s\n' "$today" > "$OUT/.last-scheduled-day"
            run_once scheduled || true
            last_pull="$(date +%s)"
        fi
        now_s="$(date +%s)"
        if [[ "$BACKUP_PULL_INTERVAL_HOURS" =~ ^[0-9]+$ ]] && (( BACKUP_PULL_INTERVAL_HOURS > 0 )) \
           && (( now_s - last_pull >= BACKUP_PULL_INTERVAL_HOURS * 3600 )); then
            last_pull="$now_s"
            [[ "$BACKUP_ENABLED" == "1" ]] && run_pull
        fi
        sleep 20
    done
}

case "${1:-daemon}" in
    daemon)   cmd_daemon ;;
    run-once) run_once "${2:-manual}" ;;
    pull)     prepare_dirs; run_pull ;;
    check)    cmd_check ;;
    *) echo "usage: $0 {daemon|run-once|pull|check}" >&2; exit 2 ;;
esac
