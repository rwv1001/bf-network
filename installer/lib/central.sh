# shellcheck shell=bash
# =============================================================================
# bf-central helpers. Sourced by installer.sh.
#
# Used by BOTH the normal install (setup_bf_central in installer.sh) and
# --restore-central, so there is one copy of "how a central server is built".
#
# Callers set: CENTRAL_SSH_KEY, CENTRAL_SSH_USER, CENTRAL_HOST, REAL_HOME.
# =============================================================================

central_ssh_raw() {
    ssh -i "$CENTRAL_SSH_KEY" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$REAL_HOME/.ssh/known_hosts" \
        "${CENTRAL_SSH_USER}@${CENTRAL_HOST}" "$@"
}

central_ssh() {
    local cmd="$1"
    central_ssh_raw "bash -lc $(remote_quote "$cmd")"
}

central_sudo() {
    central_ssh_raw sudo -n bash -lc "$(remote_quote "$1")"
}

central_scp_to() {
    local src="$1" dest="$2"
    scp -i "$CENTRAL_SSH_KEY" \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$REAL_HOME/.ssh/known_hosts" \
        "$src" "${CENTRAL_SSH_USER}@${CENTRAL_HOST}:${dest}"
}

# Install Docker, clone bf-central into ~/bf-central, write its .env and start it.
#
# Normal install: new DB_PASSWORD and ADMIN_KEY are generated (ADMIN_KEY is left
# set for the caller, which registers the site with it).
#
# --restore-central: CENTRAL_ENV_OVERRIDE_FILE points at env/central.env from
# the backup bundle and is installed unchanged, so the rebuilt server keeps the
# old ADMIN_KEY and database password and no site has to be re-registered.
_install_bf_central_stack() {
    info "Installing bf-central on ${CENTRAL_HOST}"
    echo "Checking / installing prerequisites on ${CENTRAL_HOST}..."

    local bootstrap_tmp
    bootstrap_tmp="$(mktemp)"
    cat > "$bootstrap_tmp" <<'REMOTE_EOF'
#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq
    command -v git >/dev/null 2>&1 || sudo apt-get install -y git
    command -v curl >/dev/null 2>&1 || sudo apt-get install -y curl
else
    echo "WARNING: apt-get not found – please ensure git is installed manually."
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not found – installing..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$(whoami)" || true
fi

if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but the current user may not yet have permission."
    echo "You may need to log out/in or run: newgrp docker"
fi

echo "Prerequisites ready."
REMOTE_EOF

    central_scp_to "$bootstrap_tmp" "/tmp/bf-central-bootstrap.sh"
    rm -f "$bootstrap_tmp"
    central_ssh "bash /tmp/bf-central-bootstrap.sh && rm -f /tmp/bf-central-bootstrap.sh"

    central_ssh "git clone --branch main https://github.com/rwv1001/bf-central.git \$HOME/bf-central"

    local central_env_tmp
    central_env_tmp="$(mktemp)"
    chmod 600 "$central_env_tmp"

    if [ -n "${CENTRAL_ENV_OVERRIDE_FILE:-}" ]; then
        [ -s "$CENTRAL_ENV_OVERRIDE_FILE" ] || die "Central .env from the backup is missing or empty: $CENTRAL_ENV_OVERRIDE_FILE"
        cp "$CENTRAL_ENV_OVERRIDE_FILE" "$central_env_tmp"
        echo "Using the .env recovered from the backup (same ADMIN_KEY and database password as before)."
    else
        CENTRAL_DB_PASSWORD="$(generate_secret)"
        ADMIN_KEY="$(generate_secret)"
        CENTRAL_DOMAIN_CLEAN="$(printf '%s' "$CENTRAL_API_URL" | sed -E 's|^https?://||; s|/.*||')"

        prompt_default GUNICORN_WORKERS \
            "Gunicorn workers for bf-central" \
            "2" \
            "central_gunicorn_workers"

        {
            write_env_line DB_PASSWORD "$CENTRAL_DB_PASSWORD"
            write_env_line ADMIN_KEY "$ADMIN_KEY"
            write_env_line GUNICORN_WORKERS "$GUNICORN_WORKERS"
            write_env_line CENTRAL_DOMAIN "$CENTRAL_DOMAIN_CLEAN"
            # Lets central back itself up; empty = central self-backup off.
            write_env_line BACKUP_PUBLIC_KEY "${BACKUP_PUBLIC_KEY:-}"
        } > "$central_env_tmp"
    fi

    central_scp_to "$central_env_tmp" "/tmp/bf-central.env"
    rm -f "$central_env_tmp"
    central_ssh "mv /tmp/bf-central.env \$HOME/bf-central/.env && chmod 600 \$HOME/bf-central/.env"
    central_ssh "cd \$HOME/bf-central && (docker compose up -d --build || docker-compose up -d --build)"

    echo "Waiting for bf-central API to become ready..."
    sleep 12
}

# -----------------------------------------------------------------------------
# --restore-central BUNDLE
#
# Builds bf-central on a NEW, empty server from a central backup bundle.
# Touches nothing on any site, switch or the tunnel VPS.
# -----------------------------------------------------------------------------
restore_central_from_bundle() {
    recovery_real_user
    recovery_open_bundle "$RECOVERY_BUNDLE" central
    trap recovery_cleanup EXIT

    info "Restore bf-central from a backup"
    recovery_print_summary

    local env_file="$RECOVERY_DIR/env/central.env" db_file="$RECOVERY_DIR/db/central.json" domain
    [ -s "$env_file" ] && [ -s "$db_file" ] || die "This bundle has no env/central.env or db/central.json; it is not a usable central backup."
    domain="$(grep -E '^CENTRAL_DOMAIN=' "$env_file" | head -1 | cut -d= -f2- | tr -d "'\"" || true)"

    cat <<EOF

What this does
  1. Installs Docker and bf-central on a NEW server that you name below.
  2. Gives it the SAME settings as the lost server (ADMIN_KEY, database password,
     domain ${domain:-?}), taken from the backup.
  3. Loads the backed-up database: every site's API key and push secret, all
     users, devices and the pending queue as they were when the backup was made.

What this does NOT do
  - It does not touch any site, switch or the tunnel VPS.
  - It does not change DNS. Sites keep calling ${domain:-the central domain}; when this
    finishes you must point that name at the new server (step shown at the end).
  - It does not bring back the sites' stored bundles; each site uploads a fresh
    one on its next nightly run.
  - Anything registered after the backup was made is not in it. Sites re-send
    what they still have queued; a device registered in that gap may need
    registering again.

It refuses to run against a server that already has ~/bf-central.

EOF

    read -r -p "SSH address of the NEW central server (its IP, unless DNS already points there): " CENTRAL_HOST
    [ -n "$CENTRAL_HOST" ] || die "No server given."
    read -r -p "SSH username on that server [ubuntu]: " CENTRAL_SSH_USER
    CENTRAL_SSH_USER="${CENTRAL_SSH_USER:-ubuntu}"
    read -r -p "SSH private key for that server [$REAL_HOME/.ssh/bf-central]: " CENTRAL_SSH_KEY
    CENTRAL_SSH_KEY="${CENTRAL_SSH_KEY:-$REAL_HOME/.ssh/bf-central}"
    [ -f "$CENTRAL_SSH_KEY" ] || die "Key not found: $CENTRAL_SSH_KEY"

    echo "Testing SSH access to ${CENTRAL_SSH_USER}@${CENTRAL_HOST} ..."
    central_ssh_raw "echo central SSH OK" >/dev/null 2>&1 \
        || die "Cannot SSH to ${CENTRAL_SSH_USER}@${CENTRAL_HOST} with $CENTRAL_SSH_KEY. Nothing was changed."
    central_ssh_raw "sudo -n true" >/dev/null 2>&1 \
        || die "${CENTRAL_SSH_USER} needs passwordless sudo on ${CENTRAL_HOST}. Nothing was changed."

    if central_ssh "test -e \$HOME/bf-central"; then
        die "${CENTRAL_HOST} already has ~/bf-central. Nothing was changed.
This mode only builds a new server. If that directory is a failed earlier attempt,
log in, check it holds nothing you need, remove it yourself
(cd ~/bf-central && docker compose down; cd ~ && sudo rm -rf bf-central) and run this again."
    fi

    local answer
    read -r -p "Type RESTORE to build bf-central on ${CENTRAL_HOST} from this backup: " answer
    [ "$answer" = "RESTORE" ] || die "Not confirmed. Nothing was changed."

    CENTRAL_API_URL="http://${domain:-$CENTRAL_HOST}"
    CENTRAL_ENV_OVERRIDE_FILE="$env_file"
    _install_bf_central_stack

    info "Waiting for the new bf-central API"
    central_ssh "cd \$HOME/bf-central && for i in \$(seq 1 60); do
        docker compose exec -T central-api python -c 'import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:5000/health\", timeout=3)' >/dev/null 2>&1 && exit 0
        sleep 2
    done
    docker compose logs --tail=40 central-api >&2
    exit 1" || die "bf-central did not start on ${CENTRAL_HOST}. The server has the software and .env but NO data yet.
Fix the cause shown above, then load the data by hand:
  docker compose exec -T central-api python restore_backup.py < central.json"

    info "Loading the backed-up database"
    central_scp_to "$db_file" "/tmp/bf-central-restore.json"
    central_ssh "chmod 600 /tmp/bf-central-restore.json; cd \$HOME/bf-central
        docker compose exec -T central-api python restore_backup.py < /tmp/bf-central-restore.json; rc=\$?
        shred -u /tmp/bf-central-restore.json 2>/dev/null || rm -f /tmp/bf-central-restore.json
        exit \$rc" || die "The database load failed; see the message above. Nothing was half-loaded (it is one transaction)."

    cat <<EOF

============================================================================
bf-central is rebuilt on ${CENTRAL_HOST}.  Still to do, by you:
============================================================================
 1. DNS: point ${domain:-the central domain} at the new server's public IP.
 2. Firewall / cloud security list: allow inbound TCP 80 (and 443 if you use
    HTTPS for central) to the new server.
 3. Check from any machine:   curl http://${domain:-<central domain>}/health
    expected: {"status":"ok"}
 4. On one site, open Admin -> Backups and press "Back up now"; "Sent to
    central" should show a new time. That proves the site's old API key works
    against the rebuilt server.
 5. If the installer state for your sites still holds the old server as the
    bf-central SSH host, update it next time you run the installer for a site:
      sudo ./installer.sh --config <site> --forget-answer central_ssh_host
============================================================================
EOF
}
