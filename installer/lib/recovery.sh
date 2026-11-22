# shellcheck shell=bash
# =============================================================================
# Disaster-recovery modes for installer.sh. Sourced by installer.sh.
# Operator documentation: docs/RECOVERY.md
#
# Design rule: recovery never has its own copy of install logic.
#   --restore-site   runs the NORMAL install flow against the replacement
#                    server; the functions here only feed it the old secrets,
#                    files and database at the existing checkpoints.
#   --retarget-vps   re-runs the NORMAL tunnel-VPS steps against a new VPS.
#   --clone-switch   drives the same serial expect script as a new install.
#   --restore-central is in lib/central.sh and shares the central installer.
# =============================================================================

RECOVERY_MODE=""            # init-key | inspect | restore-site | restore-central | clone-switch | retarget-vps
RECOVERY_BUNDLE=""
RECOVERY_KEY_FILE=""
RECOVERY_EXTRACT_TO=""
RECOVERY_DIR=""             # decrypted bundle (RAM-backed), set by recovery_open_bundle
RECOVERY_WORK=""
RESTORE_SITE_DIR=""         # non-empty while --restore-site is driving the install
CLONE_SWITCH_NAME=""
CLONE_SWITCH_CFG=""
CLONE_UPLINK_PORT=""
CLONE_WIPE=0
RETARGET_VPS_HOST=""

# .env keys that describe the replacement machine rather than the site. On
# --restore-site these come from the installer; every other key keeps the value
# it had in the backup.
RESTORE_ENV_KEYS_FROM_INSTALLER="WAN_IFACE PI_DEFAULT_ROUTE_DEV GIT_REPO_DIR PORTAL_UID PORTAL_GID SWITCH_KEY_PATH ORACLE_VPS_SSH_KEY_PATH ORACLE_VPS_HOST"

recovery_real_user() {
    if [ -z "${REAL_USER:-}" ]; then
        if [ -n "${SUDO_USER:-}" ]; then REAL_USER="$SUDO_USER"; else REAL_USER="$(logname 2>/dev/null || whoami)"; fi
    fi
    [ -n "${REAL_HOME:-}" ] || REAL_HOME="$(eval echo "~$REAL_USER")"
}

recovery_tmpdir() {
    local base="/dev/shm"
    [ -d "$base" ] && [ -w "$base" ] || base="${TMPDIR:-/tmp}"
    mktemp -d "$base/bf-recovery.XXXXXX"
}

recovery_cleanup() {
    if [ -n "${RECOVERY_WORK:-}" ] && [ -d "$RECOVERY_WORK" ]; then
        find "$RECOVERY_WORK" -type f -exec shred -u {} + 2>/dev/null || true
        rm -rf "$RECOVERY_WORK"
    fi
    RECOVERY_WORK=""
}

recovery_default_key_file() {
    printf '%s' "${RECOVERY_KEY_FILE:-$REAL_HOME/bf-recovery-key/bf-recovery-private.asc}"
}

# -----------------------------------------------------------------------------
# --init-recovery-key
# -----------------------------------------------------------------------------
recovery_init_key() {
    recovery_real_user
    local dir="$REAL_HOME/bf-recovery-key" priv pub pass1 pass2 home fpr
    priv="$dir/bf-recovery-private.asc"
    pub="$dir/bf-recovery-public.b64"

    info "Create the organisation's backup recovery key"
    cat <<EOF
One key pair protects the backups of EVERY site and of bf-central.

  PUBLIC half   goes into .env on every site and on bf-central as
                BACKUP_PUBLIC_KEY. It can only lock backups, never open them,
                so it is safe on the servers.
  PRIVATE half  stays with you, protected by a passphrase. It is needed only
                when you run a recovery mode of this installer. It must NEVER
                be copied to a site server, bf-central or the tunnel VPS.

If you lose the private half or forget its passphrase, every backup made with
it is permanently unreadable. There is no other way in.

Run this ONCE for the organisation, not once per site.
EOF
    if [ -e "$priv" ]; then
        die "A recovery key already exists at $priv. Nothing was changed.
Creating another would make existing backups unreadable with the new key.
To see its public half again:  cat $pub"
    fi

    while true; do
        read -r -s -p "Passphrase for the recovery private key (at least 12 characters): " pass1; echo
        read -r -s -p "Repeat the passphrase: " pass2; echo
        [ "$pass1" = "$pass2" ] || { echo "They did not match."; continue; }
        [ "${#pass1}" -ge 12 ] || { echo "Use at least 12 characters."; continue; }
        break
    done

    RECOVERY_WORK="$(recovery_tmpdir)"; trap recovery_cleanup EXIT
    home="$RECOVERY_WORK/gnupg"; mkdir -p "$home"; chmod 700 "$home"

    printf '%s' "$pass1" | gpg --homedir "$home" --batch --quiet --pinentry-mode loopback --passphrase-fd 0 \
        --quick-generate-key "bf-network backup recovery <recovery@bf-network.invalid>" ed25519 cert never \
        || die "Could not generate the key."
    fpr="$(gpg --homedir "$home" --batch --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')"
    printf '%s' "$pass1" | gpg --homedir "$home" --batch --quiet --pinentry-mode loopback --passphrase-fd 0 \
        --quick-add-key "$fpr" cv25519 encr never || die "Could not add the encryption subkey."

    mkdir -p "$dir"; chmod 700 "$dir"
    printf '%s' "$pass1" | gpg --homedir "$home" --batch --quiet --pinentry-mode loopback --passphrase-fd 0 \
        --armor --export-secret-keys "$fpr" > "$priv" || die "Could not export the private key."
    chmod 600 "$priv"
    gpg --homedir "$home" --batch --export "$fpr" | base64 -w0 > "$pub"
    printf '%s\n' "$fpr" > "$dir/fingerprint.txt"

    # Prove the saved files work before anybody relies on them.
    local probe="$RECOVERY_WORK/probe" check="$RECOVERY_WORK/check" home2="$RECOVERY_WORK/gnupg2"
    mkdir -p "$home2"; chmod 700 "$home2"
    base64 -d "$pub" > "$RECOVERY_WORK/pub.bin"
    printf 'bf-recovery-selftest' | gpg --homedir "$home2" --batch --quiet --yes --trust-model always \
        --recipient-file "$RECOVERY_WORK/pub.bin" --output "$probe" --encrypt \
        || die "Self-test failed (encrypt). Delete $dir and try again."
    gpg --homedir "$home2" --batch --quiet --import "$priv" 2>/dev/null || true
    printf '%s' "$pass1" | gpg --homedir "$home2" --batch --quiet --pinentry-mode loopback --passphrase-fd 0 \
        --output "$check" --decrypt "$probe" 2>/dev/null || true
    [ "$(cat "$check" 2>/dev/null)" = "bf-recovery-selftest" ] \
        || die "Self-test failed (decrypt). Delete $dir and try again."
    chown -R "$REAL_USER":"$REAL_USER" "$dir"

    cat <<EOF

============================================================================
Recovery key created and self-tested.
============================================================================
Fingerprint : $fpr
Private key : $priv      (passphrase-protected)
Public key  : $pub

NOW:
 1. Copy $priv to at least two places that are NOT network
    servers (e.g. two USB sticks kept in different buildings) and store the
    passphrase separately (password manager and/or sealed paper copy).
 2. On EVERY site, add this line to the server's .env, then run
    'docker compose up -d --build backup' there:

BACKUP_PUBLIC_KEY=$(cat "$pub")

    (When you next run this installer for a site it asks for the same value,
    so that it is not lost when .env is regenerated.)
 3. Add the same line to ~/bf-central/.env on the central server and run
    'docker compose up -d --build' there.
 4. On each site open Admin -> Backups: the fingerprint shown must equal the
    one above. If it differs, somebody put a different key there.
============================================================================
EOF
}

# -----------------------------------------------------------------------------
# Opening a bundle
# -----------------------------------------------------------------------------
recovery_manifest_get() {   # dotted.path -> value ('' if absent)
    python3 - "$RECOVERY_DIR/manifest.json" "$1" <<'PY'
import json, sys
try:
    v = json.load(open(sys.argv[1]))
    for part in sys.argv[2].split("."):
        v = v[part]
    print(v if not isinstance(v, (dict, list)) else json.dumps(v))
except Exception:
    print("")
PY
}

recovery_env_get() {        # KEY from the bundle's site .env
    local line
    line="$(grep -E "^$1=" "$RECOVERY_DIR/repo/.env" 2>/dev/null | tail -n1)" || true
    line="${line#*=}"
    if [[ "$line" == \"*\" || "$line" == \'*\' ]]; then line="${line:1:${#line}-2}"; fi
    printf '%s' "$line"
}

# recovery_open_bundle FILE [site|central]
recovery_open_bundle() {
    local file="$1" want="${2:-}" keyfile pass home kind
    [ -n "$file" ] && [ -f "$file" ] || die "Backup bundle not found: ${file:-<none given>}"
    case "$(basename "$file")" in
        bfbackup-*.tar.gz.gpg) ;;
        *) die "$(basename "$file") is not a bf-network backup bundle (expected a name like bfbackup-site-<id>-<date>.tar.gz.gpg)." ;;
    esac
    recovery_real_user
    keyfile="$(recovery_default_key_file)"
    [ -f "$keyfile" ] || die "Recovery private key not found: $keyfile
Copy bf-recovery-private.asc from your offline copy onto this machine and pass
its path with --recovery-key FILE. Bundles cannot be opened without it."

    if [ -n "${BF_RECOVERY_PASSPHRASE:-}" ]; then
        pass="$BF_RECOVERY_PASSPHRASE"
    else
        read -r -s -p "Passphrase of the recovery private key: " pass; echo
    fi

    RECOVERY_WORK="$(recovery_tmpdir)"
    chmod 700 "$RECOVERY_WORK"
    home="$RECOVERY_WORK/gnupg"; mkdir -p "$home" "$RECOVERY_WORK/bundle"; chmod 700 "$home"
    gpg --homedir "$home" --batch --quiet --import "$keyfile" 2>/dev/null \
        || { recovery_cleanup; die "Could not read the recovery private key file $keyfile."; }

    # Keep numeric owners: root-owned NPM/acme data must stay root-owned when
    # it is pushed to the replacement server.
    if ! printf '%s' "$pass" | gpg --homedir "$home" --batch --quiet --pinentry-mode loopback --passphrase-fd 0 \
            --decrypt "$file" 2>"$RECOVERY_WORK/gpg.err" \
            | tar --numeric-owner -xzf - -C "$RECOVERY_WORK/bundle" 2>"$RECOVERY_WORK/tar.err"; then
        local why; why="$(head -n 3 "$RECOVERY_WORK/gpg.err" "$RECOVERY_WORK/tar.err" 2>/dev/null | tr '\n' ' ')"
        recovery_cleanup
        die "Could not open $(basename "$file"): wrong passphrase, wrong recovery key, or a damaged file.
$why"
    fi
    rm -rf "$home"
    RECOVERY_DIR="$RECOVERY_WORK/bundle"

    [ "$(recovery_manifest_get format)" = "1" ] || { recovery_cleanup; die "Unknown bundle format; this installer is too old (or the file is not a bundle)."; }
    kind="$(recovery_manifest_get kind)"
    if [ -n "$want" ] && [ "$kind" != "$want" ]; then
        recovery_cleanup
        die "This is a '$kind' backup but this mode needs a '$want' backup. Nothing was changed."
    fi
}

recovery_print_summary() {
    local kind; kind="$(recovery_manifest_get kind)"
    echo "  Bundle type        : $kind"
    echo "  Site / owner       : $(recovery_manifest_get site_id)"
    echo "  Created (UTC)      : $(recovery_manifest_get created_utc)"
    echo "  Encrypted to key   : $(recovery_manifest_get recovery_key_fingerprint)"
    if [ "$kind" = "site" ]; then
        echo "  Server hostname    : $(recovery_manifest_get hostname)"
        echo "  bf-network commit  : $(recovery_manifest_get git_commit)"
        echo "  Portal URL         : $(recovery_manifest_get portal_url)"
        echo "  Switches           : $(recovery_manifest_get switch_hosts)"
        echo "  Tunnel VPS         : $(recovery_manifest_get tunnel_vps.user)@$(recovery_manifest_get tunnel_vps.host)  https port $(recovery_manifest_get tunnel_vps.https_port), admin ssh port $(recovery_manifest_get tunnel_vps.admin_ssh_tunnel_port)"
        echo "  Tables without data: $(recovery_manifest_get database.table_data_excluded)"
        local f
        echo "  Switch configs     :"
        for f in "$RECOVERY_DIR"/switches/*.cfg; do [ -f "$f" ] && echo "      $(basename "$f")"; done
    else
        echo "  Rows               : $(recovery_manifest_get row_counts)"
        echo "  Sites known        : $(recovery_manifest_get sites)"
    fi
    echo
    echo "  NOTE: a bundle is encrypted but not signed. Anyone holding the PUBLIC key"
    echo "  could have made it. Only restore a bundle that came from a server you"
    echo "  trust, and check the site, date and commit above are what you expect."
}

# --inspect-backup FILE [--extract-to DIR]
recovery_inspect() {
    recovery_open_bundle "$RECOVERY_BUNDLE"
    trap recovery_cleanup EXIT
    info "Backup bundle $(basename "$RECOVERY_BUNDLE")"
    recovery_print_summary
    echo
    echo "Contents:"
    (cd "$RECOVERY_DIR" && find . -mindepth 1 -maxdepth 3 | sort | sed 's/^\.\//  /')
    if [ -n "$RECOVERY_EXTRACT_TO" ]; then
        [ ! -e "$RECOVERY_EXTRACT_TO" ] || die "$RECOVERY_EXTRACT_TO already exists; choose a new directory."
        mkdir -p "$RECOVERY_EXTRACT_TO"; chmod 700 "$RECOVERY_EXTRACT_TO"
        cp -a "$RECOVERY_DIR/." "$RECOVERY_EXTRACT_TO/"
        echo
        echo "Extracted to $RECOVERY_EXTRACT_TO (root only)."
        echo "WARNING: that directory now holds PLAINTEXT secrets: .env, SSH private keys,"
        echo "TLS keys and password hashes. Delete it as soon as you are done:"
        echo "  sudo find $RECOVERY_EXTRACT_TO -type f -exec shred -u {} + ; sudo rm -rf $RECOVERY_EXTRACT_TO"
    else
        echo
        echo "Nothing was written to disk. Add --extract-to DIR to keep a plaintext copy."
    fi
}

# -----------------------------------------------------------------------------
# --restore-site: hooks called from the normal install flow
# -----------------------------------------------------------------------------

# Called once the installer state is loaded, before any prompt.
restore_site_prepare() {
    recovery_open_bundle "$RECOVERY_BUNDLE" site
    RESTORE_SITE_DIR="$RECOVERY_DIR"
    local site commit answer key value name src dest
    site="$(recovery_manifest_get site_id)"

    info "Restore a site server from a backup"
    recovery_print_summary
    cat <<EOF

What this does
  It runs the normal installer against a REPLACEMENT server, with these
  differences:
    - the code is checked out at the commit recorded in the backup;
    - DB_PASSWORD, SECRET_KEY, RADIUS_SECRET and the other secrets are the OLD
      ones from the backup, so the switches' RADIUS secret still matches;
    - .env is the backed-up .env; only machine-specific keys are refreshed
      (${RESTORE_ENV_KEYS_FROM_INSTALLER});
    - after the empty database is created, the backed-up database is loaded
      (users, devices, admins, VLANs, switch ports, DHCP reservations);
    - NPM, Pi-hole settings, certificates, SSH keys and switch policy files are
      copied back from the backup.

What this does NOT do
  - It does NOT configure or touch any switch: they are assumed to be running.
  - It does NOT register the site with bf-central again: the old API key is in
    the backed-up .env and still valid.
  - It does not restore traffic history; that is never backed up.
  - The UniFi controller is installed empty. Restore its own .unf backup from
    the UniFi setup screen (copies, if any, are put in ~/unifi-restore).

DANGER — read this
  The installer wipes ~/bf-network and the Docker data on the machine it is
  pointed at, exactly as a first install does. Point it ONLY at the
  replacement server. If the original server is still running and you name
  it by mistake, its database is destroyed. The dead server must stay off
  the network: two servers with the same addresses will break DHCP.

Before continuing
  - The replacement runs Raspberry Pi OS / Debian with SSH enabled.
  - The installer's SSH key for the server is in its authorized_keys.
  - If its address or login differs from the old server's, stop now and run:
      sudo ./installer.sh --config <site> --forget-answer PI_WIFI_IP
      sudo ./installer.sh --config <site> --forget-answer PI_USER
    then start --restore-site again.

EOF
    if [ "${#SAVED_ANSWERS[@]}" -eq 0 ]; then
        cat <<EOF
NOTE: this installer has no saved answers for this site, so every question of
a first install will be asked. Answer them as they were answered originally
(the backup's .env wins for almost everything, but VLANs, addresses and the
network interface are taken from your answers). If the site's installer state
was backed up, it is better to stop, put it back and start again:
  sudo ./installer.sh --inspect-backup <bundle> --extract-to /root/bundle
  then copy /root/bundle/installer-store/state/*.gpg to /var/lib/bf-network-installer/

EOF
    fi
    read -r -p "Type the site id ($site) to restore it onto the replacement server: " answer
    [ "$answer" = "$site" ] || { recovery_cleanup; die "Not confirmed. Nothing was changed."; }

    # Same code as the backup, so the database schema matches.
    commit="$(recovery_manifest_get git_commit)"
    if [[ "$commit" =~ ^[0-9a-f]{7,40}$ ]]; then
        SAVED_ANSWERS[bf_repo_ref]="$commit"
    else
        echo "WARNING: the backup does not record a commit; using the saved/default git ref."
    fi

    # Same secrets as before.
    for key in DB_PASSWORD SECRET_KEY RADIUS_SECRET PIHOLE_WEBPASSWORD; do
        value="$(recovery_env_get "$key")"
        [ -n "$value" ] && GENERATED_SECRETS[$key]="$value"
    done

    # The site is already registered at bf-central; reuse its credentials.
    value="$(recovery_env_get CENTRAL_API_KEY)"
    [ -n "$value" ] && SAVED_ANSWERS[central_api_key]="$value"
    value="$(recovery_env_get CENTRAL_PUSH_SECRET)"
    [ -n "$value" ] && SAVED_ANSWERS[central_push_secret]="$value"
    COMPLETED_STEPS[central_site_registered]="done"
    COMPLETED_STEPS[central_site_env_update]="done"

    # Every server-side step must run again on the new machine.
    for key in "${!COMPLETED_STEPS[@]}"; do
        case "$key" in
            pi_*|setup_pi_*|seed_isp_routers|nat_logger_setup|validate_pi_server)
                unset "COMPLETED_STEPS[$key]" ;;
        esac
    done

    # SSH keys: the switches and the VPS only know the OLD keys, so the
    # installer must use those and never generate new ones.
    src="$RESTORE_SITE_DIR/home/.ssh"
    name="$(basename "$(recovery_env_get SWITCH_KEY_PATH)")"
    dest="${SAVED_ANSWERS[switch_key_path]:-$REAL_HOME/.ssh/$name}"
    if [ -n "$name" ] && [ -f "$src/$name" ] && [ -f "$src/$name.pub" ]; then
        _restore_place_key "$src/$name" "$dest"
        _restore_place_key "$src/$name.pub" "$dest.pub"
        SAVED_ANSWERS[switch_key_path]="$dest"
        COMPLETED_STEPS[switch_key_ready]="done"
    else
        echo "WARNING: the backup holds no switch SSH key ($name). If the installer creates a new one, the server will NOT be able to manage the switches until the key is installed on each of them."
    fi
    name="$(basename "$(recovery_env_get ORACLE_VPS_SSH_KEY_PATH)")"
    dest="${SAVED_ANSWERS[oracle_key_path]:-$REAL_HOME/.ssh/oracle_restored_$site}"
    if [ -n "$name" ] && [ -f "$src/$name" ]; then
        _restore_place_key "$src/$name" "$dest"
        [ -f "$src/$name.pub" ] && _restore_place_key "$src/$name.pub" "$dest.pub"
        SAVED_ANSWERS[oracle_key_path]="$dest"
    fi

    state_save
    echo "Backup accepted. Continuing with the normal install against the replacement server."
}

_restore_place_key() {   # never overwrites a key that is already there
    local from="$1" to="$2"
    if [ -e "$to" ]; then
        cmp -s "$from" "$to" || echo "NOTE: keeping existing $to (differs from the copy in the backup)."
        return 0
    fi
    mkdir -p "$(dirname "$to")"
    install -m 600 -o "$REAL_USER" -g "$REAL_USER" "$from" "$to"
    echo "Restored key from backup: $to"
}

# Called just before the switch loop: the switches are alive, leave them alone.
restore_site_skip_switches() {
    local j
    for j in "${!IPS[@]}"; do
        COMPLETED_STEPS["switch_${j}_configured"]="done"
    done
    echo "Restore mode: switch configuration is skipped for all ${#IPS[@]} switch(es)."
}

# restore_merge_env GENERATED_ENV — rewrite it as: backed-up .env, with only the
# machine-specific keys taken from what the installer just generated.
restore_merge_env() {
    local generated="$1" backup="$RESTORE_SITE_DIR/repo/.env" out
    [ -s "$backup" ] || die "The backup has no .env; cannot restore."
    out="$(mktemp)"; chmod 600 "$out"
    awk -v keys="$RESTORE_ENV_KEYS_FROM_INSTALLER" '
        function keyof(line) { return (line ~ /^[A-Za-z_][A-Za-z0-9_]*=/) ? substr(line, 1, index(line, "=") - 1) : "" }
        BEGIN { n = split(keys, k, " "); for (i = 1; i <= n; i++) machine[k[i]] = 1 }
        FNR == NR { key = keyof($0); if (key != "") gen[key] = $0; next }
        {
            key = keyof($0)
            if (key != "") seen[key] = 1
            if (key != "" && (key in machine) && (key in gen)) { print gen[key]; next }
            print
        }
        END { for (key in gen) if (!(key in seen)) print gen[key] }
    ' "$generated" "$backup" > "$out"
    echo "Restored .env from the backup. Keys taken from this install instead: $(
        for key in $RESTORE_ENV_KEYS_FROM_INSTALLER; do
            [ "$(grep -E "^$key=" "$out" | tail -n1)" != "$(grep -E "^$key=" "$backup" | tail -n1)" ] && printf '%s ' "$key"
        done)"
    cat "$out" > "$generated"
    shred -u "$out" 2>/dev/null || rm -f "$out"
}

# Called after the data wipe and before the stack starts.
restore_site_push_files() {
    info "Restore mode: copying the backed-up files to the server"
    local tarball script parts=() p
    tarball="$(mktemp "$RECOVERY_WORK/files.XXXXXX.tgz")"
    for p in repo/kea/config repo/scripts/scriptdata repo/mdns/peers.json repo/shared/ssh-known-hosts \
             repo/npm repo/pihole home root installer-store host; do
        [ -e "$RESTORE_SITE_DIR/$p" ] && parts+=("$p")
    done
    tar --numeric-owner -C "$RESTORE_SITE_DIR" -czf "$tarball" "${parts[@]}"

    script="$(mktemp)"
    cat > "$script" <<'REMOTE_EOF'
#!/bin/bash
# args: <repo dir> <service user>
set -euo pipefail
umask 077
repo="$1"; user="$2"; home="$(getent passwd "$user" | cut -d: -f6)"
t="$(mktemp -d)"
trap 'find "$t" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$t"; rm -f /tmp/bf-restore-files.tgz' EXIT
tar --numeric-owner -xzf /tmp/bf-restore-files.tgz -C "$t"

# Repository-local state (NPM, Pi-hole settings, switch policy, Kea config).
[ -d "$t/repo" ] && cp -a "$t/repo/." "$repo/"
for d in kea/config scripts/scriptdata mdns shared/ssh-known-hosts; do
    [ -e "$repo/$d" ] && chown -R "$user:$user" "$repo/$d"
done

# The service user's SSH keys. authorized_keys is merged, never replaced: it is
# how this installer is logged in right now.
mkdir -p "$home/.ssh"
if [ -d "$t/home/.ssh" ]; then
    for f in "$t/home/.ssh"/*; do
        [ -f "$f" ] || continue
        b="$(basename "$f")"
        case "$b" in authorized_keys|known_hosts) continue ;; esac
        [ -e "$home/.ssh/$b" ] || cp -p "$f" "$home/.ssh/$b"
    done
    if [ -f "$t/home/.ssh/authorized_keys" ]; then
        touch "$home/.ssh/authorized_keys"
        cat "$t/home/.ssh/authorized_keys" >> "$home/.ssh/authorized_keys"
        awk 'NF && !seen[$0]++' "$home/.ssh/authorized_keys" > "$home/.ssh/authorized_keys.new"
        mv "$home/.ssh/authorized_keys.new" "$home/.ssh/authorized_keys"
    fi
fi
chown -R "$user:$user" "$home/.ssh"; chmod 700 "$home/.ssh"
find "$home/.ssh" -type f ! -name '*.pub' -exec chmod 600 {} +

[ -d "$t/home/certs" ] && { mkdir -p "$home/certs"; cp -a "$t/home/certs/." "$home/certs/"; chown -R "$user:$user" "$home/certs"; }
if [ -d "$t/home/unifi/data/data/backup" ]; then
    mkdir -p "$home/unifi-restore"; cp -a "$t/home/unifi/data/data/backup/." "$home/unifi-restore/"
    chown -R "$user:$user" "$home/unifi-restore"
fi

# Certificate tooling and the installer's certificate store.
[ -d "$t/root/.acme.sh" ] && [ ! -e /root/.acme.sh ] && cp -a "$t/root/.acme.sh" /root/.acme.sh
[ -f "$t/root/.bunny_api_key" ] && [ ! -e /root/.bunny_api_key ] && install -m 600 "$t/root/.bunny_api_key" /root/.bunny_api_key
if [ -d "$t/installer-store" ]; then
    mkdir -p /var/lib/bf-network-installer
    cp -a "$t/installer-store/." /var/lib/bf-network-installer/
fi

# Host network files are NOT applied: the installer regenerates them for this
# machine's network interface. The old ones are kept for comparison only.
if [ -d "$t/host" ]; then
    rm -rf /root/bf-restore-reference; mkdir -p /root/bf-restore-reference
    cp -a "$t/host" /root/bf-restore-reference/
fi
echo "Backed-up files are in place."
REMOTE_EOF
    pi_scp_to "$tarball" "/tmp/bf-restore-files.tgz"
    pi_scp_to "$script" "/tmp/bf-restore-files.sh"
    rm -f "$script"; shred -u "$tarball" 2>/dev/null || rm -f "$tarball"
    pi_sudo "chmod 600 /tmp/bf-restore-files.tgz; bash /tmp/bf-restore-files.sh $(shell_quote "$PI_REPO_DIR") $(shell_quote "$PI_USER"); rc=\$?; rm -f /tmp/bf-restore-files.sh /tmp/bf-restore-files.tgz; exit \$rc" \
        || die "Copying the backed-up files to the server failed. Re-run the same command to try again; nothing else has been started yet."
}

# Called inside the compose start-up step, once PostgreSQL is up and before the
# rest of the stack starts.
restore_site_database() {
    local q_repo="$1" dump="$RESTORE_SITE_DIR/db/captive_portal.sql" counts
    [ -s "$dump" ] || die "The backup has no database dump."
    info "Restore mode: loading the backed-up database"
    pi_scp_to "$dump" "/tmp/bf-restore-db.sql"
    pi_sudo "chmod 600 /tmp/bf-restore-db.sql; cd $q_repo
        docker compose exec -T db psql -q -X -v ON_ERROR_STOP=1 -U portal_user -d captive_portal < /tmp/bf-restore-db.sql >/tmp/bf-restore-db.log 2>&1; rc=\$?
        shred -u /tmp/bf-restore-db.sql 2>/dev/null || rm -f /tmp/bf-restore-db.sql
        [ \$rc -eq 0 ] || tail -n 20 /tmp/bf-restore-db.log >&2
        rm -f /tmp/bf-restore-db.log
        exit \$rc" || die "Loading the database failed (see above). The stack has NOT been started.
It is safe to run the same --restore-site command again: the load replaces whatever is there."
    counts="$(pi_sudo "cd $q_repo && docker compose exec -T db psql -X -At -U portal_user -d captive_portal -c \"select 'users='||(select count(*) from users)||' devices='||(select count(*) from devices)||' admins='||(select count(*) from admins)\"" | tr -d '\r' || true)"
    echo "Database restored: $counts"
    # The ISP routers and VLAN mappings came back with the database.
    COMPLETED_STEPS[seed_isp_routers]="done"
    state_save
}

restore_site_finished() {
    cat <<EOF

----------------------------------------------------------------------------
RESTORE COMPLETE — check these before telling users it is back
----------------------------------------------------------------------------
 1. Admin portal: log in with your OLD admin account; users and devices are listed.
 2. A registered device gets its usual address and internet access.
 3. Admin -> Switch Health shows every switch (the server is using the old key).
 4. Admin -> Backups -> "Back up now" succeeds and "Sent to central" updates.
 5. UniFi: restore the controller's own backup from its setup screen if needed.
 6. The old server must never be reconnected as it is. Wipe it first.
Reference copy of the old host network files: /root/bf-restore-reference on the server.
----------------------------------------------------------------------------
EOF
}

# -----------------------------------------------------------------------------
# --retarget-vps NEWHOST: hooks called from the normal install flow
# -----------------------------------------------------------------------------
retarget_vps_prepare() {
    local old="${SAVED_ANSWERS[ORACLE_VPS_HOST]:-}" answer key
    [ -n "$old" ] || die "No saved install found in this installer state, so there is nothing to retarget.
Use the same --config NAME as the site's install. If that state is lost, restore it
from a backup first (docs/RECOVERY.md, 'Getting the installer state back')."
    [ "$old" != "$RETARGET_VPS_HOST" ] || echo "NOTE: the saved VPS is already $old; its configuration will be rebuilt in place."

    info "Move this site's public front door to a new tunnel VPS"
    cat <<EOF
  Old VPS : $old
  New VPS : $RETARGET_VPS_HOST

What this does (all with the normal install steps, re-run)
  - On the NEW VPS: installs nginx, adds this site's proxy entries and TLS
    certificate (copied from the site server), and the SSH settings for the
    admin tunnel.
  - On the site server: writes the new VPS address into .env and into the
    UniFi tunnel settings, restarts the tunnels and the admin SSH tunnel unit.

What this does NOT do
  - It does not change DNS: you must point this site's names at the new VPS.
  - It does not touch the old VPS, the switches, the database or UniFi data.
  - It moves ONLY this site. Run it once per site that used the old VPS
    (each with its own --config NAME).

Before continuing
  - The new VPS accepts the SAME SSH key as the old one for its login user
    (add the public key when creating the VM), with passwordless sudo.
  - Its firewall / cloud security list allows inbound TCP 22, 80 and 443.
  - NOTE: .env on the site server is regenerated from the installer's saved
    answers, as on any installer run. Settings added to .env by hand that the
    installer does not know are lost; compare with the copy it leaves at
    .env.before-retarget.

EOF
    read -r -p "Type the new VPS address ($RETARGET_VPS_HOST) to continue: " answer
    [ "$answer" = "$RETARGET_VPS_HOST" ] || die "Not confirmed. Nothing was changed."

    SAVED_ANSWERS[ORACLE_VPS_HOST]="$RETARGET_VPS_HOST"
    for key in "${!SAVED_ANSWERS[@]}"; do
        case "$key" in oracle_dns_record_created_*) unset "SAVED_ANSWERS[$key]" ;; esac
    done
    unset 'COMPLETED_STEPS[oracle_vps_configured]' 'COMPLETED_STEPS[oracle_vps_admin_sshd]' \
          'COMPLETED_STEPS[pi_env_file]' 'COMPLETED_STEPS[pi_compose_up]' 'COMPLETED_STEPS[pi_ssh_reverse_tunnel]'
    state_save
}

# Called just before the VPS is configured: give the new VPS the certificate
# the site already holds, so it does not depend on DNS having moved yet.
retarget_vps_seed_certificate() {
    ssh_drop_stale_host_key "$ORACLE_VPS_HOST"
    oracle_vps_ssh_raw "echo VPS SSH OK" >/dev/null 2>&1 \
        || die "Cannot SSH to ${ORACLE_VPS_USER}@${ORACLE_VPS_HOST} with $ORACLE_KEY_PATH. Nothing was changed on the VPS or the site."
    pi_sudo "cp -p $(shell_quote "$PI_REPO_DIR/.env") $(shell_quote "$PI_REPO_DIR/.env.before-retarget")" || true
    if pi_ssh "test -s $(shell_quote "$CERT_STORE_DIR/fullchain.pem") && test -s $(shell_quote "$CERT_STORE_DIR/privkey.pem")"; then
        echo "Copying the site's TLS certificate to the new VPS."
        install_vps_tls_from_pi_store
    else
        echo "WARNING: no certificate in the site's store ($CERT_STORE_DIR)."
        echo "The VPS will ask Let's Encrypt for one, which only works once DNS for"
        echo "$MAIN_DOMAIN already points at $ORACLE_VPS_HOST."
    fi
}

# Called after the server steps: move the UniFi front door too, without
# reinstalling the controller (that would erase its data).
retarget_vps_finish() {
    if [ -n "${UNIFI_FQDN:-}" ] && pi_ssh "test -f /home/$PI_USER/unifi/docker-compose.yml"; then
        info "Pointing the UniFi tunnel at the new VPS"
        oracle_update_oracle_vps_nginx "$UNIFI_FQDN" "https" "${ORACLE_VPS_UNIFI_HTTPS_PORT:-9446}" "$MAIN_DOMAIN"
        pi_sudo "cd /home/$PI_USER/unifi \
            && sed -i -E 's|^ORACLE_VPS_HOST=.*|ORACLE_VPS_HOST=${ORACLE_VPS_HOST}|' .env \
            && sed -i -E 's|^([[:space:]]*ORACLE_VPS_HOST:).*|\\1 ${ORACLE_VPS_HOST}|' docker-compose.yml \
            && docker compose up -d"
    fi
    cat <<EOF

----------------------------------------------------------------------------
VPS MOVE COMPLETE for this site — still to do, by you
----------------------------------------------------------------------------
 1. DNS: point ${MAIN_DOMAIN}${UNIFI_FQDN:+ and ${UNIFI_FQDN}} at ${ORACLE_VPS_HOST}.
 2. After DNS has moved, open https://${MAIN_DOMAIN} from outside the site.
 3. Repeat --retarget-vps for every other site that used the old VPS.
 4. Compare .env with .env.before-retarget on the site server and delete the copy.
----------------------------------------------------------------------------
EOF
}

# -----------------------------------------------------------------------------
# --clone-switch: put a saved start-up configuration onto a replacement 5130
# -----------------------------------------------------------------------------
recovery_clone_switch() {
    recovery_real_user
    local cfg="" work
    if [ -n "$CLONE_SWITCH_CFG" ]; then
        [ -f "$CLONE_SWITCH_CFG" ] || die "Switch configuration file not found: $CLONE_SWITCH_CFG"
        cfg="$CLONE_SWITCH_CFG"
    else
        [ -n "$RECOVERY_BUNDLE" ] || die "--clone-switch needs --switch-config FILE, or --from-backup BUNDLE (a site backup)."
        recovery_open_bundle "$RECOVERY_BUNDLE" site
        trap recovery_cleanup EXIT
        cfg="$RECOVERY_DIR/switches/5130-startup-${CLONE_SWITCH_NAME}.cfg"
        if [ ! -f "$cfg" ]; then
            echo "No saved configuration for a switch called '$CLONE_SWITCH_NAME' in this backup. It holds:"
            local have
            for have in "$RECOVERY_DIR"/switches/5130-startup-*.cfg; do
                [ -f "$have" ] || continue
                have="$(basename "$have" .cfg)"; echo "  ${have#5130-startup-}"
            done
            die "Run again with --clone-switch NAME using one of the names above."
        fi
    fi

    local sysname tftp_line tftp_ip tftp_path svi_vlan svi_ip svi_mask
    sysname="$(awk '$1=="sysname"{print $2; exit}' "$cfg" | tr -d '\r')"
    grep -q '^ *sysname ' "$cfg" && grep -q 'interface Vlan-interface' "$cfg" \
        || die "$cfg does not look like a Comware start-up configuration."

    # The nightly job in the config says where the switch sends its backup; the
    # same server and path are where the clone will fetch it from.
    tftp_line="$(grep -oE 'tftp [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ put (flash:/)?startup\.cfg [^ ]+' "$cfg" | head -n1 | tr -d '\r' || true)"
    tftp_ip="$(awk '{print $2}' <<<"$tftp_line")"
    tftp_path="$(awk '{print $NF}' <<<"$tftp_line")"
    [ -n "$tftp_ip" ] && [ -n "$tftp_path" ] \
        || die "This configuration has no nightly 'tftp … put startup.cfg …' job, so the TFTP server cannot be worked out. It was probably not written by this installer; clone it by hand."

    # Management address: the Vlan-interface in the same /24 as the TFTP server.
    local svi_line
    svi_line="$(tr -d '\r' < "$cfg" | awk -v want="${tftp_ip%.*}." '
        /^interface Vlan-interface/ { v = $2; sub(/Vlan-interface/, "", v) }
        /^ ip address / && v != "" { if (index($3, want) == 1) { print v, $3, $4; exit } }
        /^#/ { v = "" }')"
    read -r svi_vlan svi_ip svi_mask <<<"$svi_line" || true
    [ -n "${svi_vlan:-}" ] || die "Could not find the switch's management address (a Vlan-interface in ${tftp_ip%.*}.0/24) in $cfg."

    # Which port carries the management VLAN to the rest of the network?
    local -a trunks=()
    mapfile -t trunks < <(tr -d '\r' < "$cfg" | awk '
        /^interface (Ten-)?GigabitEthernet/ { name = $2; desc = ""; trunk = 0 }
        /^ description / && name != "" { desc = substr($0, 14) }
        /^ port link-type trunk/ && name != "" { trunk = 1 }
        /^#/ { if (name != "" && trunk) print name "|" desc; name = "" }')
    [ "${#trunks[@]}" -gt 0 ] || die "No trunk port found in $cfg."
    local uplink="$CLONE_UPLINK_PORT" t
    if [ -z "$uplink" ]; then
        echo "Trunk ports in the saved configuration:"
        for t in "${trunks[@]}"; do printf '  %-28s %s\n' "${t%%|*}" "${t#*|}"; done
        read -r -p "Which of these ports is cabled to the rest of the network on the REPLACEMENT switch? [${trunks[0]%%|*}]: " uplink
        uplink="${uplink:-${trunks[0]%%|*}}"
    fi
    printf '%s\n' "${trunks[@]%%|*}" | grep -qx "$uplink" || die "'$uplink' is not a trunk port in the saved configuration."

    # Temporary configuration: just enough to reach the TFTP server.
    local uplink_lines pvid bootstrap
    uplink_lines="$(tr -d '\r' < "$cfg" | awk -v p="$uplink" '
        $1=="interface" { on = ($2 == p) ; next }
        /^#/ { on = 0 }
        on && /^ port (link-type|trunk permit|trunk pvid) / { print }')"
    pvid="$(awk '/trunk pvid vlan/{print $5}' <<<"$uplink_lines" | head -n1)"
    bootstrap="vlan ${svi_vlan}
quit
${pvid:+vlan ${pvid}
quit
}interface ${uplink}
${uplink_lines}
quit
interface Vlan-interface${svi_vlan}
 ip address ${svi_ip} ${svi_mask}
quit"

    # The switch will load whatever the TFTP server hands out under that name.
    # TFTP has no authentication, so compare it with the file chosen here.
    local served tftp_note
    served="$(mktemp)"
    if curl -s --max-time 10 -o "$served" "tftp://${tftp_ip}/${tftp_path}" 2>/dev/null && [ -s "$served" ]; then
        if cmp -s "$served" "$cfg"; then
            tftp_note="VERIFIED: the TFTP server is serving exactly the file shown above."
        else
            tftp_note="WARNING: the TFTP server is serving a DIFFERENT file under that name than the
  one you chose. The switch gets the SERVER's copy. If you meant the file above,
  upload it first (command below) and run this again; if the server's copy is
  the newer one you want, download and read it before continuing."
        fi
    else
        tftp_note="NOT CHECKED: this machine cannot reach the TFTP server, so it could not confirm
  that the server holds the file shown above. Make sure it does (see below)."
    fi
    rm -f "$served"

    info "Clone switch ${sysname:-?} onto a replacement HP 5130"
    cat <<EOF
  Saved configuration : $cfg
  Switch name         : ${sysname:-?}
  Management address  : ${svi_ip} ${svi_mask} (VLAN ${svi_vlan})
  Uplink used to fetch: ${uplink}
  Fetched from        : tftp://${tftp_ip}/${tftp_path}
  ${tftp_note}

What this does, over the serial cable
  1. Logs in to the replacement switch$( [ "$CLONE_WIPE" -eq 1 ] && echo " and resets it to factory defaults (--wipe)").
  2. Types a TEMPORARY configuration (the lines below) so it can reach the
     site server. This is never saved.
  3. Makes the switch download the saved configuration by TFTP as bf-clone.cfg,
     sets it as the start-up configuration and reboots WITHOUT saving.
  After the reboot the replacement is an exact copy: same name, address, VLANs,
  ACLs, port roles, RADIUS settings and admin logins as the dead switch.

Temporary configuration:
$(sed 's/^/    /' <<<"$bootstrap")

Before continuing
  - The DEAD switch is unplugged from the network (same address!).
  - The replacement is the same model, with firmware at least as new as the
    dead one's (first line of the saved file: $(grep -m1 '^ *version ' "$cfg" | tr -d '\r' | sed 's/^ *//')).
  - The serial cable is in the replacement's console port, and its port
    ${uplink} is cabled where the dead switch's was.
  - The file is on the TFTP server as ${tftp_path}. If the site server is
    running it already is (the dead switch put it there nightly). If you are
    using an OLDER copy from a backup, or the server was rebuilt, upload it
    into the TFTP directory first (on a site server that is
    /var/lib/tftpboot/switch-backups):
      scp <the .cfg> <user>@<site server>:/tmp/x.cfg
      ssh <user>@<site server> sudo install -o tftp -g tftp -m 644 /tmp/x.cfg /var/lib/tftpboot/switch-backups/${tftp_path}

If the download fails, nothing has been saved on the replacement: power-cycle
it and it is as it was.

EOF
    local answer console_pass
    read -r -p "Type CLONE to continue: " answer
    [ "$answer" = "CLONE" ] || die "Not confirmed. Nothing was changed."
    read -r -s -p "Current console password of the replacement switch (empty if factory default): " console_pass; echo

    install_expect
    [ -f "$EXPECT_SCRIPT" ] || die "Could not find expect script at $EXPECT_SCRIPT."
    chmod +x "$EXPECT_SCRIPT"
    detect_switch_serial_port || die "No switch detected on a serial port."
    free_serial_port "$DETECTED_PORT"

    local cmd=("$EXPECT_SCRIPT" -port "$DETECTED_PORT" -cp "$console_pass" -vlan-config "$bootstrap"
               -clone-tftp-server "$tftp_ip" -clone-tftp-path "$tftp_path")
    if [ "$CLONE_WIPE" -eq 1 ]; then
        # A wiped switch insists on an admin password at first login. This one
        # lives only until the reboot into the cloned configuration.
        cmd+=(-wipe -np "$(generate_secret | head -c 20)aA1!")
    fi
    echo "Calling Expect on $DETECTED_PORT (passwords not shown)."
    "${cmd[@]}" || die "Cloning did not complete (see the messages above). The replacement switch has NOT been given the saved configuration."

    cat <<EOF

============================================================================
${sysname:-The switch} is rebooting into the cloned configuration (2–4 minutes).
============================================================================
 1. When it is up:  ping ${svi_ip}
 2. Its SSH host key is new. On the site server, remove the dead switch's key
    so the portal can log in again:
      ssh-keygen -f ~/bf-network/shared/ssh-known-hosts/known_hosts -R ${svi_ip}
      ssh-keygen -f ~/.ssh/known_hosts -R ${svi_ip}
    (and the same for ~/.ssh/known_hosts on this installer machine).
 3. Admin -> Switch Health should show it within a few minutes; then use
    Admin -> ISP Routers -> "Reapply ACL blocks" so current per-device blocks
    are pushed to it.
 4. Devices on its ports re-authenticate by themselves.
============================================================================
EOF
}

# Copy the (already encrypted) installer state to the site server, so that it
# is inside the next backup bundle and a lost installer machine is not a
# second disaster.
push_installer_state_to_site() {
    [ -f "$STATE_FILE" ] || return 0
    local name; name="$(basename "$STATE_FILE")"
    if pi_scp_to "$STATE_FILE" "/tmp/$name" 2>/dev/null \
        && pi_sudo "mkdir -p /var/lib/bf-network-installer/state && install -m 600 -o root -g root /tmp/$name /var/lib/bf-network-installer/state/$name && rm -f /tmp/$name" 2>/dev/null; then
        echo "Installer state (encrypted with your installer passphrase) copied to the server for inclusion in backups."
    else
        echo "NOTE: could not copy the installer state to the server; it is only on this machine ($STATE_FILE)."
    fi
}
