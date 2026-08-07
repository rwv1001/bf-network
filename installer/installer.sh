#!/bin/bash
set -euo pipefail

# =============================================================================
# HP 5130 + Raspberry Pi bf-network Initial Setup Wizard
# =============================================================================
# This script configures HP 5130 switches and then installs/configures the
# bf-network Pi server over the Pi's WiFi SSH address.
#
# Assumptions intentionally baked in:
#   - The Pi already has Raspberry Pi OS installed and SSH enabled over WiFi.
#   - User VLANs are the VLAN_LIST entered below; management and wired VLANs are
#     separate prompts and are not re-asked in the Pi section.
#   - User VLAN prefixes are /24.
#   - The first configured switch is the gateway switch for user/wired/mgmt VLANs.
#   - The Pi uses systemd-networkd files under /etc/systemd/network.
#   - wlan0 is left enabled for recovery/admin access.
#   - Docker/Docker Compose may be installed on the Pi.
#   - The bf-network repository is replaced at the chosen path.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECT_SCRIPT="$SCRIPT_DIR/test-switch-temp.exp"
BF_REPO_URL="https://github.com/rwv1001/bf-network.git"
BF_REPO_BRANCH="main"

# Encrypted, resumable installer state. Override with --state-file PATH.
STATE_FILE="${BF_INSTALL_STATE_FILE:-/var/lib/bf-network-installer/state.gpg}"
RESET_STATE=0
FORGET_ANSWER_KEY=""
FORGET_STEP_KEY=""
FORGET_ALL_STEPS=0
FORGET_SECRET_KEY=""
FORGET_ALL_SECRETS=0
SHOW_STATE_ONLY=0
STATE_READY=0
STATE_PASSPHRASE=""
STATE_FORMAT_EXPECTED="bf-network-installer-state-v1"

declare -A SAVED_ANSWERS=()
declare -A COMPLETED_STEPS=()
declare -A GENERATED_SECRETS=()

# =============================================================================
# Basic helpers
# =============================================================================

die() {
    echo "ERROR: $*" >&2
    exit 1
}

info() {
    echo
    echo "=== $* ==="
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --state-file)
                [ "$#" -ge 2 ] || die "--state-file requires a path."
                STATE_FILE="$2"
                shift 2
                ;;
            --reset-state)
                RESET_STATE=1
                shift
                ;;
            --forget-answer)
                [ "$#" -ge 2 ] || die "--forget-answer requires an answer key."
                FORGET_ANSWER_KEY="$2"
                shift 2
                ;;
            --forget-step)
                [ "$#" -ge 2 ] || die "--forget-step requires a completed-step key."
                FORGET_STEP_KEY="$2"
                shift 2
                ;;
            --forget-steps)
                FORGET_ALL_STEPS=1
                shift
                ;;
            --forget-secret)
                [ "$#" -ge 2 ] || die "--forget-secret requires a secret name (e.g. DB_PASSWORD)."
                FORGET_SECRET_KEY="$2"
                shift 2
                ;;
            --forget-secrets)
                FORGET_ALL_SECRETS=1
                shift
                ;;    
            --show-progress)
                SHOW_STATE_ONLY=1
                shift
                ;;
            -h|--help)
                cat <<'EOF'
Usage: sudo ./installer.sh [options]

Options:
  --state-file PATH       Use a different encrypted state file.
  --reset-state           Delete the saved state and start from scratch.
  --forget-answer KEY     Forget one cached prompt answer, then continue.
  --forget-step KEY       Forget one completed checkpoint, then exit.
  --forget-steps          Forget all completed checkpoints (keep answers/secrets), then exit.
  --forget-secret NAME    Forget one generated secret (e.g. DB_PASSWORD), then exit.
  --forget-secrets        Forget all generated secrets, then exit.
  --show-progress         Decrypt the state, display checkpoints, and exit.
  -h, --help              Show this help.

The default state file is /var/lib/bf-network-installer/state.gpg.
EOF
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done
}

answer_exists() {
    local key="$1"
    [[ -v "SAVED_ANSWERS[$key]" ]]
}

save_answer() {
    local key="$1"
    local value="$2"
    SAVED_ANSWERS["$key"]="$value"
    state_save
}

invalidate_answer() {
    local key="$1"
    unset 'SAVED_ANSWERS[$key]'
    state_save
}

step_done() {
    local key="$1"
    [[ "${COMPLETED_STEPS[$key]:-}" == "done" ]]
}

complete_step() {
    local key="$1"
    COMPLETED_STEPS["$key"]="done"
    state_save
    echo "Checkpoint saved: $key"
}

ensure_generated_secret() {
    local var_name="$1"
    if [[ -v "GENERATED_SECRETS[$var_name]" ]]; then
        printf -v "$var_name" '%s' "${GENERATED_SECRETS[$var_name]}"
        return 0
    fi

    local value
    value="$(generate_secret)"
    GENERATED_SECRETS["$var_name"]="$value"
    printf -v "$var_name" '%s' "$value"
    state_save
}

state_plain_tmp() {
    local base="/dev/shm"
    [ -d "$base" ] && [ -w "$base" ] || base="$(dirname "$STATE_FILE")"
    mktemp "$base/bf-network-installer-state.XXXXXX"
}

state_save() {
    [ "$STATE_READY" -eq 1 ] || return 0

    local plain_tmp encrypted_tmp
    plain_tmp="$(state_plain_tmp)"
    encrypted_tmp="${STATE_FILE}.tmp.$$"
    chmod 600 "$plain_tmp"

    {
        printf 'STATE_FORMAT=%q\n' "$STATE_FORMAT_EXPECTED"
        declare -p SAVED_ANSWERS COMPLETED_STEPS GENERATED_SECRETS \
            | sed 's/^declare /declare -g /'
    } > "$plain_tmp"

    if ! printf '%s' "$STATE_PASSPHRASE" | \
        GNUPGHOME="$STATE_GNUPGHOME" gpg --batch --yes --quiet \
            --pinentry-mode loopback --passphrase-fd 0 \
            --symmetric --cipher-algo AES256 \
            --s2k-mode 3 --s2k-digest-algo SHA512 \
            --output "$encrypted_tmp" "$plain_tmp"; then
        rm -f "$plain_tmp" "$encrypted_tmp"
        die "Failed to encrypt installer state."
    fi

    chmod 600 "$encrypted_tmp"
    mv -f "$encrypted_tmp" "$STATE_FILE"
    shred -u "$plain_tmp" 2>/dev/null || rm -f "$plain_tmp"
}

state_load() {
    local plain_tmp
    plain_tmp="$(state_plain_tmp)"
    chmod 600 "$plain_tmp"

    if ! printf '%s' "$STATE_PASSPHRASE" | \
        GNUPGHOME="$STATE_GNUPGHOME" gpg --batch --yes --quiet \
            --pinentry-mode loopback --passphrase-fd 0 \
            --decrypt "$STATE_FILE" > "$plain_tmp"; then
        rm -f "$plain_tmp"
        return 1
    fi

    # The encrypted file is integrity protected by GnuPG and stored in a
    # root-only directory. It contains only declare statements produced here.
    # shellcheck disable=SC1090
    source "$plain_tmp"
    shred -u "$plain_tmp" 2>/dev/null || rm -f "$plain_tmp"

    [ "${STATE_FORMAT:-}" = "$STATE_FORMAT_EXPECTED" ] || \
        die "Unsupported or corrupt installer state format."
}

prompt_state_passphrase_new() {
    if [ -n "${BF_INSTALL_STATE_PASSPHRASE:-}" ]; then
        STATE_PASSPHRASE="$BF_INSTALL_STATE_PASSPHRASE"
        return 0
    fi

    local first second
    while true; do
        read -r -s -p "Create a passphrase for the encrypted installer state: " first
        echo
        read -r -s -p "Confirm the installer-state passphrase: " second
        echo
        if [ "$first" != "$second" ]; then
            echo "Passphrases did not match."
            continue
        fi
        if [ "${#first}" -lt 4 ]; then
            echo "Use at least 4 characters."
            continue
        fi
        STATE_PASSPHRASE="$first"
        return 0
    done
}

prompt_state_passphrase_existing() {
    if [ -n "${BF_INSTALL_STATE_PASSPHRASE:-}" ]; then
        STATE_PASSPHRASE="$BF_INSTALL_STATE_PASSPHRASE"
        return 0
    fi

    read -r -s -p "Installer-state passphrase: " STATE_PASSPHRASE
    echo
}

state_progress() {
    echo
    echo "Encrypted state file: $STATE_FILE"
    echo "Saved prompt answers: ${#SAVED_ANSWERS[@]}"
    echo "Saved generated secrets: ${#GENERATED_SECRETS[@]}"
    echo "Completed checkpoints:"
    if [ "${#COMPLETED_STEPS[@]}" -eq 0 ]; then
        echo "  (none)"
    else
        local key
        while IFS= read -r key; do
            echo "  - $key"
        done < <(printf '%s\n' "${!COMPLETED_STEPS[@]}" | sort)
    fi
    echo
}

state_init() {
    local state_dir
    state_dir="$(dirname "$STATE_FILE")"
    mkdir -p "$state_dir"
    chmod 700 "$state_dir"

    [ ! -L "$STATE_FILE" ] || die "Refusing to use a symlink as the state file: $STATE_FILE"

    STATE_GNUPGHOME="$state_dir/gnupg"
    mkdir -p "$STATE_GNUPGHOME"
    chmod 700 "$STATE_GNUPGHOME"

    exec 9>"$state_dir/installer.lock"
    flock -n 9 || die "Another installer process is already using $STATE_FILE."

    if [ "$RESET_STATE" -eq 1 ]; then
        rm -f "$STATE_FILE"
        echo "Removed saved installer state: $STATE_FILE"
    fi

    if [ -f "$STATE_FILE" ]; then
        local attempt
        for attempt in 1 2 3; do
            prompt_state_passphrase_existing
            if state_load; then
                echo "Loaded encrypted installer state."
                STATE_READY=1
                break
            fi
            STATE_PASSPHRASE=""
            echo "Could not decrypt the state file (attempt $attempt of 3)."
        done
        [ "$STATE_READY" -eq 1 ] || die "Unable to decrypt $STATE_FILE."
    else
        prompt_state_passphrase_new
        STATE_READY=1
        state_save
        echo "Created encrypted installer state: $STATE_FILE"
    fi

    if [ -n "$FORGET_ANSWER_KEY" ]; then
        if answer_exists "$FORGET_ANSWER_KEY"; then
            unset 'SAVED_ANSWERS[$FORGET_ANSWER_KEY]'
            state_save
            echo "Forgot saved answer: $FORGET_ANSWER_KEY"
        else
            echo "No saved answer exists for key: $FORGET_ANSWER_KEY"
        fi

        state_progress
        exit 0
    fi
    
    if [ -n "$FORGET_STEP_KEY" ]; then
        if [[ "${COMPLETED_STEPS[$FORGET_STEP_KEY]:-}" == "done" ]]; then
            unset 'COMPLETED_STEPS[$FORGET_STEP_KEY]'
            state_save
            echo "Forgot completed checkpoint: $FORGET_STEP_KEY"
        else
            echo "No completed checkpoint exists for key: $FORGET_STEP_KEY"
        fi

        state_progress
        exit 0
    fi

    if [ "$FORGET_ALL_STEPS" -eq 1 ]; then
        COMPLETED_STEPS=()
        state_save
        echo "Forgot all completed checkpoints (answers and generated secrets kept)."
        state_progress
        exit 0
    fi
    
    if [ "$FORGET_ALL_SECRETS" -eq 1 ]; then
        GENERATED_SECRETS=()
        state_save
        echo "Forgot all generated secrets."
        state_progress
        exit 0
    fi

    if [ -n "$FORGET_SECRET_KEY" ]; then
        if [[ -v "GENERATED_SECRETS[$FORGET_SECRET_KEY]" ]]; then
            unset "GENERATED_SECRETS[$FORGET_SECRET_KEY]"
            state_save
            echo "Forgot generated secret: $FORGET_SECRET_KEY"
        else
            echo "No generated secret exists for key: $FORGET_SECRET_KEY"
        fi
        state_progress
        exit 0
    fi
    
    state_progress

    if [ "$SHOW_STATE_ONLY" -eq 1 ]; then
        exit 0
    fi
}

state_save_on_exit() {
    local rc=$?
    trap - EXIT
    if [ "$STATE_READY" -eq 1 ]; then
        state_save || true
    fi
    exit "$rc"
}

prompt_default() {
    local var_name="$1"
    local prompt="$2"
    local default_value="$3"
    local key="${4:-$var_name}"
    local answer=""

    if answer_exists "$key"; then
        printf -v "$var_name" '%s' "${SAVED_ANSWERS[$key]}"
        echo "Using saved answer for: $prompt"
        return 0
    fi

    read -r -p "$prompt [$default_value]: " answer
    if [ -z "$answer" ]; then
        answer="$default_value"
    fi
    printf -v "$var_name" '%s' "$answer"
    save_answer "$key" "$answer"
}

prompt_required() {
    local var_name="$1"
    local prompt="$2"
    local key="${3:-$var_name}"
    local answer=""

    if answer_exists "$key"; then
        printf -v "$var_name" '%s' "${SAVED_ANSWERS[$key]}"
        echo "Using saved answer for: $prompt"
        return 0
    fi

    while true; do
        read -r -p "$prompt: " answer
        if [ -n "$answer" ]; then
            printf -v "$var_name" '%s' "$answer"
            save_answer "$key" "$answer"
            return 0
        fi
        echo "Please enter a value."
    done
}

prompt_secret_required() {
    local var_name="$1"
    local prompt="$2"
    local key="${3:-$var_name}"
    local answer=""

    if answer_exists "$key"; then
        printf -v "$var_name" '%s' "${SAVED_ANSWERS[$key]}"
        echo "Using saved secret for: $prompt"
        return 0
    fi

    while true; do
        read -r -s -p "$prompt: " answer
        echo
        if [ -n "$answer" ]; then
            printf -v "$var_name" '%s' "$answer"
            save_answer "$key" "$answer"
            return 0
        fi
        echo "Please enter a value."
    done
}

prompt_secret_optional() {
    local var_name="$1"
    local prompt="$2"
    local key="${3:-$var_name}"
    local answer=""

    if answer_exists "$key"; then
        printf -v "$var_name" '%s' "${SAVED_ANSWERS[$key]}"
        echo "Using saved secret for: $prompt"
        return 0
    fi

    read -r -s -p "$prompt: " answer
    echo
    printf -v "$var_name" '%s' "$answer"
    save_answer "$key" "$answer"
}

prompt_line() {
    local var_name="$1"
    local prompt="$2"
    local key="${3:-$var_name}"
    local answer=""

    if answer_exists "$key"; then
        printf -v "$var_name" '%s' "${SAVED_ANSWERS[$key]}"
        echo "Using saved answer for: $prompt"
        return 0
    fi

    read -r -p "$prompt" answer
    printf -v "$var_name" '%s' "$answer"
    save_answer "$key" "$answer"
}

prompt_ack() {
    local key="$1"
    local prompt="$2"

    if answer_exists "$key"; then
        echo "Using saved acknowledgement: $prompt"
        return 0
    fi

    read -r -p "$prompt"
    save_answer "$key" "acknowledged"
}

is_yes() {
    case "${1:-}" in
        y|Y|yes|YES|Yes|true|TRUE|1) return 0 ;;
        *) return 1 ;;
    esac
}

last_octet() {
    echo "$1" | awk -F. '{print $4}'
}

first_three_octets() {
    echo "$1" | cut -d'/' -f1 | cut -d'.' -f1-3
}

join_by_comma() {
    local IFS=,
    echo "$*"
}

join_by_space() {
    local IFS=' '
    echo "$*"
}

csv_append() {
    local existing="$1"
    local item="$2"
    if [ -z "$existing" ]; then
        echo "$item"
    else
        echo "$existing,$item"
    fi
}

shell_quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\''/g")"
}

remote_quote() {
    shell_quote "$1"
}

generate_secret() {
    # URL- and sed-safe: no +, /, =, or whitespace
    openssl rand -base64 48 | tr -d '\n+/=' | head -c 48
}

env_escape() {
    printf '%s' "$1" | sed "s/'/'\"'\"'/g"
}

write_env_line() {
    local key="$1"
    local value="$2"
    printf "%s='%s'\n" "$key" "$(env_escape "$value")"
}

# =============================================================================
# Local dependency installation
# =============================================================================

install_apt_package_for_command() {
    local command_name="$1"
    local package_name="$2"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "$command_name is not installed. Installing $package_name now..."
        apt-get update -qq
        apt-get install -y "$package_name"
        command -v "$command_name" >/dev/null 2>&1 || die "Failed to install $command_name. Please install package $package_name manually."
        echo "$command_name installed successfully."
    fi
}

install_ipcalc() {
    install_apt_package_for_command ipcalc ipcalc
}

install_expect() {
    install_apt_package_for_command expect expect
}

install_xxd() {
    install_apt_package_for_command xxd xxd
}

install_openssl() {
    install_apt_package_for_command openssl openssl
}

install_sshpass() {
    install_apt_package_for_command sshpass sshpass
}

install_gpg() {
    install_apt_package_for_command gpg gnupg
}

# =============================================================================
# Switch serial detection and interface helpers
# =============================================================================

detect_switch_serial_port() {
    echo "Scanning for HP 5130 switches on serial ports..."

    local -a detected_ports=()

    for port in /dev/ttyUSB{0..7}; do
        [ -e "$port" ] || continue

        echo "Testing $port ..."

        for attempt in 1 2 3; do
            if [ "$attempt" -gt 1 ]; then
                echo "  Retrying $port (attempt $attempt/3)..."
                sleep 5
            fi

            stty -F "$port" 9600 cs8 -cstopb -parenb raw -echo 2>/dev/null || continue
            timeout 0.5 cat < "$port" > /dev/null 2>&1 || true
            printf '\r\r' > "$port"
            sleep 1

            response="$(timeout 6 cat < "$port" 2>/dev/null || true)"

            if echo "$response" | grep -qiE 'Line aux|Automatic configuration|Login:|Password:|<|]'; then
                echo "  ? HP switch detected on $port"
                detected_ports+=("$port")
                break
            fi
        done
    done

    if [ "${#detected_ports[@]}" -eq 0 ]; then
        echo "No HP switch detected on any serial port."
        return 1
    fi

    if [ "${#detected_ports[@]}" -eq 1 ]; then
        DETECTED_PORT="${detected_ports[0]}"
        echo "Using only detected port: $DETECTED_PORT"
        return 0
    fi

    # Multiple ports found — let user choose
    echo
    echo "Multiple serial ports detected:"
    for i in "${!detected_ports[@]}"; do
        echo "  $((i+1))) ${detected_ports[$i]}"
    done

    while true; do
        read -r -p "Select port number [1-${#detected_ports[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#detected_ports[@]}" ]; then
            DETECTED_PORT="${detected_ports[$((choice-1))]}"
            echo "Selected: $DETECTED_PORT"
            return 0
        fi
        echo "Invalid selection."
    done
}

get_interface() {
    local port="$1"
    local max_1g_port="$2"

    if [ "$port" -le "$max_1g_port" ]; then
        echo "GE1/0/$port"
    else
        echo "XGE1/0/$port"
    fi
}

validate_private_base() {
    local local_base="$1"

    if ! [[ "$local_base" =~ ^[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi

    local first_octet second_octet
    IFS='.' read -r first_octet second_octet <<< "$local_base"

    if [ "$first_octet" -eq 10 ] && [ "$second_octet" -ge 0 ] && [ "$second_octet" -le 255 ]; then
        return 0
    fi

    if [ "$first_octet" -eq 172 ] && [ "$second_octet" -ge 16 ] && [ "$second_octet" -le 31 ]; then
        return 0
    fi

    if [ "$first_octet" -eq 192 ] && [ "$second_octet" -eq 168 ]; then
        return 0
    fi

    return 1
}

# =============================================================================
# Pi SSH helpers
# =============================================================================

pi_ssh_raw() {
    SSHPASS="$PI_PASSWORD" sshpass -e ssh \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$REAL_HOME/.ssh/known_hosts" \
        "$PI_USER@$PI_WIFI_IP" "$@"
}

pi_ssh() {
    local cmd="$1"
    pi_ssh_raw "bash -lc $(remote_quote "$cmd")"
}

pi_sudo() {
    local cmd="$1"
    printf '%s\n' "$PI_PASSWORD" | SSHPASS="$PI_PASSWORD" sshpass -e ssh \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$REAL_HOME/.ssh/known_hosts" \
        "$PI_USER@$PI_WIFI_IP" "sudo -S -p '' bash -lc $(remote_quote "$cmd")"
}

pi_scp_to() {
    local src="$1"
    local dest="$2"
    SSHPASS="$PI_PASSWORD" sshpass -e scp \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$REAL_HOME/.ssh/known_hosts" \
        "$src" "$PI_USER@$PI_WIFI_IP:$dest"
}

oracle_vps_ssh_raw() {
    ssh -i "$ORACLE_KEY_PATH" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$REAL_HOME/.ssh/known_hosts" \
        "${ORACLE_VPS_USER}@${ORACLE_VPS_HOST}" "$@"
}

oracle_vps_sudo() {
    oracle_vps_ssh_raw sudo -n bash -lc "$(remote_quote "$1")"
}

oracle_vps_scp_to() {
    local src="$1"
    local dest="$2"
    scp -i "$ORACLE_KEY_PATH" \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$REAL_HOME/.ssh/known_hosts" \
        "$src" "${ORACLE_VPS_USER}@${ORACLE_VPS_HOST}:$dest"
}

oracle_vps_used_ports() {
    oracle_vps_ssh_raw bash -s <<'EOF'
set -uo pipefail
{
  # Full config (needs root)
  sudo nginx -T 2>/dev/null \
    | sed -n 's/.*proxy_pass[[:space:]]\+https\?:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p'

  # Fallback: site files (no need for nginx -T)
  grep -RhoE 'proxy_pass[[:space:]]+https?://127\.0\.0\.1:[0-9]+' \
    /etc/nginx/sites-enabled /etc/nginx/sites-available 2>/dev/null \
    | sed -n 's/.*:\([0-9][0-9]*\).*/\1/p'

  # Listening sockets (sshd reverse tunnels, etc.)
  ss -ltnH 2>/dev/null | awk '
    $4 ~ /(^127\.0\.0\.1:|^\[::1\]:|^0\.0\.0\.0:|^\[::\]:)/ {
      sub(/^.*:/, "", $4)
      print $4
    }'
} | grep -E '^[0-9]+$' | sort -n -u
EOF
}


oracle_update_oracle_vps_nginx() {
    local domain="$1"
    local mode="$2"    # bootstrap | https
    local port="$3"
    local cert_primary="${4:-$domain}"   # files under /etc/letsencrypt/live/<this>/

    oracle_vps_ssh_raw python3 - "$domain" "$mode" "$port" "$cert_primary" <<'PY'
import pathlib, re, sys

domain = sys.argv[1]
mode = sys.argv[2]
port = sys.argv[3]
cert_primary = sys.argv[4]

site_file = pathlib.Path("/etc/nginx/sites-available/bf-network")
out = pathlib.Path("/tmp/bf-network-updated.conf")
text = site_file.read_text() if site_file.exists() else ""

def shared_block(domains):
    return (
        "# BEGIN bf-network installer shared-http-redirect\n"
        "server {\n"
        "    listen 80;\n"
        f"    server_name {' '.join(domains)};\n"
        "    return 301 https://$host$request_uri;\n"
        "}\n"
        "# END bf-network installer shared-http-redirect\n"
    )

def bootstrap_block(domain):
    return (
        f"# BEGIN bf-network installer {domain}\n"
        "server {\n"
        "    listen 80;\n"
        f"    server_name {domain};\n"
        "\n"
        "    location /.well-known/acme-challenge/ {\n"
        "        root /var/www/html;\n"
        "    }\n"
        "\n"
        "    location / {\n"
        "        return 200 'bf-network certificate bootstrap in progress\\n';\n"
        "        add_header Content-Type text/plain;\n"
        "    }\n"
        "}\n"
        f"# END bf-network installer {domain}\n"
    )

def https_block(domain, port, cert_primary):
    return (
        f"# BEGIN bf-network installer {domain}\n"
        "server {\n"
        "    listen 443 ssl;\n"
        f"    server_name {domain};\n"
        f"    ssl_certificate     /etc/letsencrypt/live/{cert_primary}/fullchain.pem;\n"
        f"    ssl_certificate_key /etc/letsencrypt/live/{cert_primary}/privkey.pem;\n"
        "\n"
        "    location / {\n"
        f"        proxy_pass https://127.0.0.1:{port};\n"
        "        proxy_ssl_verify off;\n"
        "        proxy_ssl_server_name on;\n"
        "        proxy_ssl_name $host;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection \"upgrade\";\n"
        "        proxy_read_timeout 86400;\n"
        "        proxy_buffering off;\n"
        "    }\n"
        "}\n"
        f"# END bf-network installer {domain}\n"
    )

shared_pat = re.compile(
    r'(?ms)^# BEGIN bf-network installer shared-http-redirect\n.*?^# END bf-network installer shared-http-redirect\n?'
)
domain_pat = re.compile(
    r'(?ms)^# BEGIN bf-network installer ' + re.escape(domain) + r'\n.*?^# END bf-network installer ' + re.escape(domain) + r'\n?'
)

# Remove only this domain’s managed block.
text = domain_pat.sub("", text).strip()

if mode == "bootstrap":
    # First run: add a temporary bootstrap block for certbot, but do not touch
    # the shared redirect block yet.
    text = (text + "\n\n" if text else "") + bootstrap_block(domain)
else:
    # Update or create the shared redirect block to include all domains.
    m = shared_pat.search(text)
    if m:
        block = m.group(0)
        sn = re.search(r"server_name\s+([^;]+);", block)
        domains = sn.group(1).split() if sn else []
        if domain not in domains:
            domains.append(domain)
        text = shared_pat.sub(shared_block(domains), text).strip()
    else:
        text = (text + "\n\n" if text else "") + shared_block([domain])

    # Add the HTTPS reverse-proxy block for this domain.
    text = (text + "\n\n" if text else "") + https_block(domain, port, cert_primary)

out.write_text(text.rstrip() + "\n")
PY

    oracle_vps_sudo "
        install -m 644 /tmp/bf-network-updated.conf /etc/nginx/sites-available/bf-network &&
        ln -sf /etc/nginx/sites-available/bf-network /etc/nginx/sites-enabled/bf-network &&
        nginx -t &&
        systemctl reload nginx &&
        rm -f /tmp/bf-network-updated.conf
    "    
}


configure_oracle_vps() {
    info "Configuring Oracle VPS"

    oracle_vps_ssh_raw "echo Oracle VPS SSH OK" >/dev/null
    oracle_vps_sudo "true" >/dev/null 2>&1 || die "Oracle VPS sudo must work without a password."

    local q_domain used_ports cert_exists
    q_domain="$(shell_quote "$MAIN_DOMAIN")"
    used_ports="$(oracle_vps_used_ports || true)"

    if printf '%s\n' "$used_ports" | grep -qx "$ORACLE_VPS_HTTPS_PORT"; then
        echo
        echo "Port ${ORACLE_VPS_HTTPS_PORT} is already in use on the Oracle VPS."
        echo "Ports currently unavailable:"
        printf '%s\n' "$used_ports"
        echo

        invalidate_answer "oracle_vps_https_port"
        while true; do
            read -r -p "Choose a different local HTTPS tunnel port on VPS [9443]: " ORACLE_VPS_HTTPS_PORT
            ORACLE_VPS_HTTPS_PORT="${ORACLE_VPS_HTTPS_PORT:-9443}"

            if ! [[ "$ORACLE_VPS_HTTPS_PORT" =~ ^[0-9]+$ ]]; then
                echo "Please enter a valid numeric port."
                continue
            fi

            if printf '%s\n' "$used_ports" | grep -qx "$ORACLE_VPS_HTTPS_PORT"; then
                echo "That port is still unavailable."
                continue
            fi

            save_answer "oracle_vps_https_port" "$ORACLE_VPS_HTTPS_PORT"
            break
        done
    fi

    oracle_vps_sudo "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq"
    oracle_vps_sudo "export DEBIAN_FRONTEND=noninteractive; apt-get install -y nginx certbot python3-certbot-nginx iptables-persistent"

    cert_exists=0
    if oracle_vps_sudo "test -s /etc/letsencrypt/live/$q_domain/fullchain.pem"; then
        cert_exists=1
    fi

    tmp_config="$(mktemp)"
    if [ "$cert_exists" -eq 0 ]; then
        oracle_update_oracle_vps_nginx "$MAIN_DOMAIN" "bootstrap" "$ORACLE_VPS_HTTPS_PORT" "$MAIN_DOMAIN"
        oracle_vps_sudo "certbot certonly --nginx -d $(shell_quote "$MAIN_DOMAIN") --non-interactive --agree-tos -m $(shell_quote "$ADMIN_EMAIL") --keep-until-expiring"
    fi

    oracle_update_oracle_vps_nginx "$MAIN_DOMAIN" "https" "$ORACLE_VPS_HTTPS_PORT" "$MAIN_DOMAIN"

    oracle_vps_sudo "
        iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT 1 -i lo -j ACCEPT
        netfilter-persistent save >/dev/null 2>&1 || true
    "

}


free_serial_port() {
    local port="$1"
    local pids raw_fuser raw_lsof p

    echo "DEBUG free_serial_port: port='$port'"

    if [ -z "$port" ]; then
        echo "DEBUG free_serial_port: empty port — nothing to do"
        return 0
    fi
    if [ ! -e "$port" ]; then
        echo "DEBUG free_serial_port: $port does not exist"
        return 0
    fi

    echo "DEBUG free_serial_port: ls -l $(ls -l "$port" 2>&1)"

    raw_fuser="$(fuser -v "$port" 2>&1 || true)"
    echo "DEBUG free_serial_port: fuser -v raw:"
    echo "$raw_fuser" | sed 's/^/  | /'

    raw_lsof="$(lsof "$port" 2>&1 || true)"
    echo "DEBUG free_serial_port: lsof raw:"
    echo "$raw_lsof" | sed 's/^/  | /'

    pids="$(fuser "$port" 2>/dev/null | tr -s '[:space:]' '\n' | grep -E '^[0-9]+$' | sort -u || true)"
    if [ -z "$pids" ]; then
        pids="$(lsof -t "$port" 2>/dev/null | sort -u || true)"
    fi

    echo "DEBUG free_serial_port: parsed PIDs: [${pids:-none}]"

    if [ -z "$pids" ]; then
        echo "Serial port $port is free."
        return 0
    fi

    for p in $pids; do
        echo "DEBUG free_serial_port: PID $p -> $(ps -o pid=,user=,args= -p "$p" 2>/dev/null || echo '(gone)')"
    done

    echo "Serial port $port is in use by PID(s): $pids — sending SIGTERM..."
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 1

    pids="$(fuser "$port" 2>/dev/null | tr -s '[:space:]' '\n' | grep -E '^[0-9]+$' | sort -u || true)"
    if [ -z "$pids" ]; then
        pids="$(lsof -t "$port" 2>/dev/null | sort -u || true)"
    fi
    echo "DEBUG free_serial_port: PIDs after SIGTERM: [${pids:-none}]"

    if [ -n "$pids" ]; then
        echo "Still busy; sending SIGKILL to: $pids"
        # shellcheck disable=SC2086
        kill -9 $pids 2>/dev/null || true
        sleep 0.5
    fi

    pids="$(fuser "$port" 2>/dev/null | tr -s '[:space:]' '\n' | grep -E '^[0-9]+$' | sort -u || true)"
    if [ -z "$pids" ]; then
        pids="$(lsof -t "$port" 2>/dev/null | sort -u || true)"
    fi
    echo "DEBUG free_serial_port: PIDs after SIGKILL: [${pids:-none}]"

    if [ -n "$pids" ]; then
        for p in $pids; do
            echo "DEBUG free_serial_port: STILL HELD by PID $p -> $(ps -o pid=,user=,args= -p "$p" 2>/dev/null || echo '(gone)')"
        done
        die "Could not free serial port $port (still in use)."
    fi

    echo "Serial port $port is now free."
}

# default_port, answer_key, prompt_text
pick_free_vps_tunnel_port() {
    local default_port="$1"
    local answer_key="$2"
    local prompt_text="$3"
    local used_ports candidate

    used_ports="$(oracle_vps_used_ports || true)"
    echo "VPS ports already in use (nginx proxy_pass + listeners):"
    if [ -n "$used_ports" ]; then
        printf '%s\n' "$used_ports" | sed 's/^/  /'
    else
        echo "  (none detected)"
    fi

    if answer_exists "$answer_key"; then
        candidate="${SAVED_ANSWERS[$answer_key]}"
        if [[ "$candidate" =~ ^[0-9]+$ ]] && ! printf '%s\n' "$used_ports" | grep -qx "$candidate"; then
            REPLY_PORT="$candidate"
            echo "Using saved free tunnel port: $candidate ($answer_key)"
            return 0
        fi
        echo "Saved port $candidate is no longer free; choosing again."
        invalidate_answer "$answer_key"
    fi

    while true; do
        read -r -p "${prompt_text} [${default_port}]: " candidate
        candidate="${candidate:-$default_port}"
        if ! [[ "$candidate" =~ ^[0-9]+$ ]] || [ "$candidate" -lt 1024 ] || [ "$candidate" -gt 65535 ]; then
            echo "Enter a TCP port number between 1024 and 65535."
            continue
        fi
        if printf '%s\n' "$used_ports" | grep -qx "$candidate"; then
            echo "Port $candidate is already in use on the VPS."
            continue
        fi
        save_answer "$answer_key" "$candidate"
        REPLY_PORT="$candidate"
        return 0
    done
}

# =============================================================================
# Pi value derivation and .env generation
# =============================================================================

derive_pi_server_values() {
    VALID_VLANS="$(join_by_comma "${VLAN_LIST[@]}")"
    VLAN_PREFIX_MAP=""
    VLAN_DEFAULTS=""
    VLAN_POOL_STATUSES=""

    for idx in "${!VLAN_LIST[@]}"; do
        local vlan="${VLAN_LIST[$idx]}"
        local name="${VLAN_NAMES[$idx]}"
        VLAN_PREFIX_MAP="$(csv_append "$VLAN_PREFIX_MAP" "${vlan}:24")"
        VLAN_DEFAULTS="$(csv_append "$VLAN_DEFAULTS" "${vlan}:${name}")"
        VLAN_POOL_STATUSES="$(csv_append "$VLAN_POOL_STATUSES" "$name")"
    done

    VLAN_DEFAULTS="$(csv_append "$VLAN_DEFAULTS" "${MANAGEMENT_VLAN}:management")"
    VLAN_DEFAULTS="$(csv_append "$VLAN_DEFAULTS" "${WIRED_VLAN}:wired_unregistered")"

    SWITCH_HOSTS_BYTES=""
    SWITCH_HOSTS=""
    for ip in "${IPS[@]}"; do
        local octet
        octet="$(last_octet "$ip")"
        SWITCH_HOSTS_BYTES="$(csv_append "$SWITCH_HOSTS_BYTES" "$octet")"
        if [ -z "$SWITCH_HOSTS" ]; then
            SWITCH_HOSTS="${LOCAL_BASE}.${MANAGEMENT_VLAN}.${octet}"
        else
            SWITCH_HOSTS="${SWITCH_HOSTS} ${LOCAL_BASE}.${MANAGEMENT_VLAN}.${octet}"
        fi
    done

    FIRST_SWITCH_OCTET="$(last_octet "${IPS[0]}")"
    NETWORK_WORD="$LOCAL_BASE"
    PORTAL_IP="${LOCAL_BASE}.${MANAGEMENT_VLAN}.${PORTAL_IP_BYTE}"
    HIJACK_DNS_IP="${LOCAL_BASE}.${MANAGEMENT_VLAN}.${HIJACK_DNS_IP_BYTE}"
    RADIUS_SERVER="$PORTAL_IP"
    
    UNREGISTERED_GW_BYTE="$FIRST_SWITCH_OCTET"
    UNREGISTERED_GW="${LOCAL_BASE}.${WIRED_VLAN}.${UNREGISTERED_GW_BYTE}"
    MGMT_GATEWAY="${LOCAL_BASE}.${MANAGEMENT_VLAN}.${FIRST_SWITCH_OCTET}"

    KEA_RENEW_TIMER=$((KEA_LEASE_LIFETIME / 2))
    KEA_REBIND_TIMER=$((KEA_LEASE_LIFETIME * 4 / 5))

    # Generated only once, then recovered from the encrypted state file.
    ensure_generated_secret DB_PASSWORD
    ensure_generated_secret SECRET_KEY
    ensure_generated_secret RADIUS_SECRET
    ensure_generated_secret PIHOLE_WEBPASSWORD

    SWITCH_KEY_BASENAME="$(basename "$KEY_PATH")"
    DOCKER_SWITCH_KEY_PATH="/keys/$SWITCH_KEY_BASENAME"

    DEFAULT_ISP_ROUTER_NAME="${ISP_NAMES[0]:-UDM}"
    DEFAULT_ISP_ROUTER_SUBNET="${ISP_NETWORK_PORTION[0]:-$(first_three_octets "$HOST_IP")}.0/24"
    UDM_HOST="${ISP_NETWORK_PORTION[0]:-$(first_three_octets "$HOST_IP")}.1"
}
sync_dns01_certificate_to_repo() {
    local q_store q_repo
    q_store="$(shell_quote "$CERT_STORE_DIR")"
    q_repo="$(shell_quote "$CERT_REPO_DIR")"

    pi_sudo "mkdir -p $q_repo"
    pi_sudo "cp -f $q_store/fullchain.pem $q_repo/fullchain.pem"
    pi_sudo "cp -f $q_store/privkey.pem $q_repo/privkey.pem"
    pi_sudo "chmod 644 $q_repo/fullchain.pem"
    pi_sudo "chmod 600 $q_repo/privkey.pem"
}

setup_dns01_certificate() {
    info "Issuing real Let's Encrypt certificate via DNS-01 (bunny.net)"

    local q_cert_dir  q_email q_domain_args=""
    CERT_DIR="$CERT_STORE_DIR"
    q_cert_dir="$(shell_quote "$CERT_DIR")"    
    q_email="$(shell_quote "$ADMIN_EMAIL")"

    # Domains: primary first, then optional UniFi (and any future SANs)
    local -a domains=("$MAIN_DOMAIN")
    if is_yes "${INSTALL_UNIFI_CONTROLLER:-y}" && [ -n "${UNIFI_FQDN:-}" ]; then
        domains+=("$UNIFI_FQDN")
    fi

    local d
    for d in "${domains[@]}"; do
        q_domain_args="$q_domain_args -d $(shell_quote "$d")"
    done

    # Install acme.sh if needed
    pi_sudo "if [ ! -f /root/.acme.sh/acme.sh ]; then
        curl https://get.acme.sh | sh -s email=$q_email
    fi"
    info "1. Installed acme.sh for DNS-01 certificate issuance."

    # Create certificate directory
    pi_sudo "mkdir -p $q_cert_dir && chmod 755 $q_cert_dir"
    info "2. Created certificate directory: $CERT_DIR"
    # Store the Bunny API key in a root-only file (never in .env)
    pi_sudo "umask 077
             printf \"%s\" $(shell_quote "$BUNNY_API_KEY") > /root/.bunny_api_key
             chmod 600 /root/.bunny_api_key"

    # Issue the certificate using the secure key file
    info "3. Issuing certificate via DNS-01"

    pi_sudo "printf \"%s\n\" \"#!/bin/sh\" \"docker restart npm >/dev/null 2>&1 || docker restart nginx-proxy-manager >/dev/null 2>&1 || exit 0\" > /usr/local/sbin/bf-network-acme-reload && chmod 755 /usr/local/sbin/bf-network-acme-reload"
    info "4. Created reload command for acme.sh to restart NPM after renewal."
    pi_sudo "export BUNNY_API_KEY=\$(cat /root/.bunny_api_key); /root/.acme.sh/acme.sh --issue --dns dns_bunny $q_domain_args --key-file $q_cert_dir/privkey.pem --fullchain-file $q_cert_dir/fullchain.pem --reloadcmd /usr/local/sbin/bf-network-acme-reload --force --debug 2 --log /tmp/acme-bunny.log || { cat /tmp/acme-bunny.log; exit 1; }"
    info "5. Certificate issuance completed. Check /tmp/acme-bunny.log for details."
    
    # Permissions on the certificate files
    pi_sudo "chmod 640 $q_cert_dir/privkey.pem"
    pi_sudo "chmod 644 $q_cert_dir/fullchain.pem"
    pi_sudo "chown -R $PI_USER:$PI_USER $q_cert_dir || true"

    info "6. Set permissions on certificate files and ownership to $PI_USER."
    pi_sudo "/root/.acme.sh/acme.sh --install-cronjob || true"
    info "7. Installed acme.sh cron job for automatic renewal."
    pi_sudo "crontab -l | grep -q acme.sh && echo 'acme.sh renewal cron is installed' || echo 'WARNING: acme.sh cron job not found'"

    info "8. Certificate issued for $MAIN_DOMAIN"

    echo "Certificate issued for $MAIN_DOMAIN"
    echo "  Full chain : $CERT_DIR/fullchain.pem"
    echo "  Private key: $CERT_DIR/privkey.pem"
}

# Install DNS-01 material onto VPS under a stable path used by all installer domains
install_vps_tls_from_pi_store() {
    local live_dir="/etc/letsencrypt/live/${MAIN_DOMAIN}"
    local q_live
    q_live="$(shell_quote "$live_dir")"

    local tmp_fc tmp_key
    tmp_fc="$(mktemp)"
    tmp_key="$(mktemp)"
    # Pull from Pi store (files already on Pi after setup_dns01)
    pi_ssh "cat $(shell_quote "$CERT_STORE_DIR/fullchain.pem")" > "$tmp_fc"
    pi_ssh "cat $(shell_quote "$CERT_STORE_DIR/privkey.pem")" > "$tmp_key"

    oracle_vps_scp_to "$tmp_fc" /tmp/bf-fullchain.pem
    oracle_vps_scp_to "$tmp_key" /tmp/bf-privkey.pem
    rm -f "$tmp_fc" "$tmp_key"

    oracle_vps_sudo "
      mkdir -p $q_live
      install -m 644 /tmp/bf-fullchain.pem $q_live/fullchain.pem
      install -m 600 /tmp/bf-privkey.pem $q_live/privkey.pem
      rm -f /tmp/bf-fullchain.pem /tmp/bf-privkey.pem
    "
}
dns_cert_files_ok() {
    pi_ssh "test -s $(shell_quote "$CERT_STORE_DIR/fullchain.pem") && test -s $(shell_quote "$CERT_STORE_DIR/privkey.pem")"
}

ensure_dns01_certificate_ready() {
    if step_done "pi_dns_certificate" && ! dns_cert_files_ok; then
        echo "DNS-01 certificate checkpoint was set, but files are missing. Regenerating."
        unset 'COMPLETED_STEPS[pi_dns_certificate]'
        state_save
    fi

    if step_done "pi_dns_certificate" && dns_cert_files_ok; then
        if is_yes "${INSTALL_UNIFI_CONTROLLER:-y}" && [ -n "${UNIFI_FQDN:-}" ]; then
            if ! pi_ssh "openssl x509 -in $(shell_quote "$CERT_STORE_DIR/fullchain.pem") -noout -text" \
                | grep -q "$UNIFI_FQDN"; then
                echo "Existing cert missing SAN $UNIFI_FQDN — re-issuing."
                unset 'COMPLETED_STEPS[pi_dns_certificate]'
                state_save
            fi
        fi
    fi

    if ! step_done "pi_dns_certificate"; then
        setup_dns01_certificate
        sync_dns01_certificate_to_repo
        complete_step "pi_dns_certificate"
        unset 'COMPLETED_STEPS[pi_npm_certificate_attach]'
        state_save
    else
        sync_dns01_certificate_to_repo
    fi
}

write_pi_env_file() {
    ENV_TMP="$(mktemp)"

    {
        write_env_line DB_HOST "127.0.0.1"
        write_env_line DB_PORT "5432"
        write_env_line DB_USER "portal_user"
        write_env_line DB_PASSWORD "$DB_PASSWORD"
        write_env_line DB_NAME "captive_portal"

        write_env_line DEEPSEEK_API_KEY ""
        write_env_line ANTHROPIC_API_KEY ""
        write_env_line SECRET_KEY "$SECRET_KEY"

        write_env_line GRAPH_TENANT_ID "$GRAPH_TENANT_ID"
        write_env_line GRAPH_CLIENT_ID "$GRAPH_CLIENT_ID"
        write_env_line GRAPH_CLIENT_SECRET "$GRAPH_CLIENT_SECRET"
        write_env_line GRAPH_FROM_EMAIL "$GRAPH_FROM_EMAIL"
        write_env_line ADMIN_EMAIL "$ADMIN_EMAIL"

        write_env_line RADIUS_SECRET "$RADIUS_SECRET"
        write_env_line RADIUS_SERVER "$RADIUS_SERVER"
        

        write_env_line PORTAL_URL "$PORTAL_URL"
        write_env_line PORTAL_POLL_URL "$PORTAL_POLL_URL"

        write_env_line NPM_ADMIN_EMAIL "$NPM_ADMIN_EMAIL"
        write_env_line NPM_ADMIN_PASSWORD "$NPM_ADMIN_PASSWORD"
        # NPM's built-in HTTP-01 cannot work in the Oracle VPS reverse-tunnel design,
        # because the public domain terminates at the VPS. The installer issues the
        # certificate separately with acme.sh/Bunny DNS-01, then reruns npm-setup
        # to import that certificate into NPM as a custom certificate.
        write_env_line NPM_SETUP_SKIP_SSL "true"
        write_env_line NPM_SETUP_FORCE_SSL "true"
        write_env_line NPM_CUSTOM_CERT_FULLCHAIN "/etc/letsencrypt/live/${MAIN_DOMAIN}/fullchain.pem"
        write_env_line NPM_CUSTOM_CERT_KEY "/etc/letsencrypt/live/${MAIN_DOMAIN}/privkey.pem"
        write_env_line PIHOLE_WEBPASSWORD "$PIHOLE_WEBPASSWORD"

        write_env_line PORTAL_FORWARD_HOST "127.0.0.1"
        write_env_line PORTAL_FORWARD_PORT "8081"
        UNIFI_FORWARD_PORT=8080
        write_env_line UNIFI_FORWARD_PORT "$UNIFI_FORWARD_PORT"
        write_env_line CAPTIVE_CHECK_HOSTS "captive.apple.com,connectivitycheck.gstatic.com,clients3.google.com,msftconnecttest.com,www.msftconnecttest.com"
        write_env_line CAPTIVE_PORTAL_IPS "$PORTAL_IP"

        write_env_line ORACLE_VPS_HOST "$ORACLE_VPS_HOST"
        write_env_line ORACLE_VPS_USER "$ORACLE_VPS_USER"
        write_env_line ORACLE_VPS_ENABLED "true"
        write_env_line ORACLE_VPS_HTTPS_PORT "$ORACLE_VPS_HTTPS_PORT"
        write_env_line ORACLE_VPS_SSH_KEY_PATH "$ORACLE_VPS_SSH_KEY_PATH"

        write_env_line SWITCH_HOSTS "$SWITCH_HOSTS"
        write_env_line WIRED_VLAN "$WIRED_VLAN"
        write_env_line SWITCH_HOSTS_BYTES "$SWITCH_HOSTS_BYTES"
        write_env_line UNREGISTERED_GW_BYTE "$UNREGISTERED_GW_BYTE"
        write_env_line UNREGISTERED_GW "$UNREGISTERED_GW"
        write_env_line MANAGEMENT_VLAN "$MANAGEMENT_VLAN"
        write_env_line PORTAL_IP_BYTE "$PORTAL_IP_BYTE"
        write_env_line HIJACK_DNS_IP_BYTE "$HIJACK_DNS_IP_BYTE"

        write_env_line PORTAL_UID "1000"
        write_env_line PORTAL_GID "1000"
        write_env_line GIT_REPO_DIR "$PI_REPO_DIR"
        write_env_line PORTAL_IP "$PORTAL_IP"
        write_env_line HIJACK_DNS_IP "$HIJACK_DNS_IP"
        write_env_line ACL_DEDUP_WINDOW "15"

        write_env_line KEA_CONTROL_SOCKET "/kea/sockets/kea4-ctrl-socket"
        write_env_line KEA_VALID_LIFETIME "$KEA_LEASE_LIFETIME"
        write_env_line KEA_RENEW_TIMER "$KEA_RENEW_TIMER"
        write_env_line KEA_REBIND_TIMER "$KEA_REBIND_TIMER"

        write_env_line EMAIL_VERIFICATION_REQUIRED "$EMAIL_VERIFICATION_REQUIRED"
        write_env_line VERIFICATION_TIMEOUT_MINUTES "$VERIFICATION_TIMEOUT_MINUTES"
        write_env_line WIFI_CONFIRM_TIMEOUT_SEC "$WIFI_CONFIRM_TIMEOUT_SEC"
        write_env_line WIFI_CONFIRM_SWEEP_ENABLED "true"
        write_env_line WIFI_CONFIRM_SWEEP_INTERVAL_SEC "30"

        write_env_line HP5130_POLICY_PATH "/scripts/scriptdata/hp5130-policy.json"
        write_env_line HP5130_CURRENT_CONFIG_PATH "/scripts/scriptdata/hp5130-current-config.json"
        write_env_line ACL_BASELINE_SCRIPT "/scripts/hp5130-acl-baseline.sh"
        write_env_line DNS_SCRIPT "/scripts/dns-hijack.sh"

        write_env_line NAT_RETENTION_DAYS "$NAT_RETENTION_DAYS"
        write_env_line DNS_DEDUP_THRESHOLD_HOURS "12"
        write_env_line DNS_RETENTION_DAYS "$DNS_RETENTION_DAYS"

        write_env_line VALID_VLANS "$VALID_VLANS"
        write_env_line VLAN_DEFAULTS "$VLAN_DEFAULTS"
        write_env_line VLAN_POOL_STATUSES "$VLAN_POOL_STATUSES"
        write_env_line NETWORK_WORD "$NETWORK_WORD"
        write_env_line VLAN_PREFIX_MAP "$VLAN_PREFIX_MAP"

        write_env_line SWITCH_PASS ""
        write_env_line USER_DEVICE_INTERFACES ""
        write_env_line SWITCH_USER "$NEW_USERNAME"
        write_env_line SWITCH_NETCONF_PORT "830"
        write_env_line SWITCH_KEY_PATH "$DOCKER_SWITCH_KEY_PATH"
        write_env_line SWITCH_PORT_LOOKUP_ENABLED "1"
        write_env_line TEST_ENV "$TEST_ENV"

        write_env_line INSTITUTION_URL "$INSTITUTION_URL"
        write_env_line INSTITUTION_BUTTON_TEXT "$INSTITUTION_BUTTON_TEXT"
        write_env_line USAGE_POLICY_TEXT "By connecting to this network, you agree to abide by the moral teaching of the Catholic Church in your internet usage. You also agree that a record will be made of the websites you visit while using this network. This recorded data will only be consulted if the English Province of the Order of the Preachers is notified that this network has been used for illegal activity. Unauthorized activities may result in loss of access and legal consequences."

        write_env_line SWITCH_REPLUG_ENABLED "$SWITCH_REPLUG_ENABLED"
        write_env_line SWITCH_REPLUG_DELAY_SEC "$SWITCH_REPLUG_DELAY_SEC"
        write_env_line SWITCH_REPLUG_ALLOWED_PREFIXES "GigabitEthernet,GE"
        write_env_line SWITCH_REPLUG_DENY_PATTERN ""
        write_env_line SWITCH_REPLUG_SCRIPT "/scripts/hp5130-replug.sh"

        write_env_line DEFAULT_ISP_ROUTER_NAME "$DEFAULT_ISP_ROUTER_NAME"
        write_env_line DEFAULT_ISP_ROUTER_SUBNET "$DEFAULT_ISP_ROUTER_SUBNET"
        write_env_line DEFAULT_ISP_ROUTER_VLAN "1"
        write_env_line DEFAULT_ISP_ROUTER_PORT ""
        write_env_line DEFAULT_ISP_ROUTER_DHCP_TRUST "true"

        write_env_line FIRMWARE_TEST_ENABLED "false"
        write_env_line UDM_HOST "$UDM_HOST"
        write_env_line UDM_WAN ""
        write_env_line MGMT_GATEWAY "$MGMT_GATEWAY"
        write_env_line USER_VLAN_MIN "${LOCAL_BASE}.2.0"
        write_env_line USER_VLAN_MAX "${LOCAL_BASE}.95.255"
        write_env_line TEL_HOST "${LOCAL_BASE}.2.1"
        write_env_line TEL_SSH_USER "root"

        write_env_line CENTRAL_API_URL ""
        write_env_line CENTRAL_API_KEY ""
        write_env_line CENTRAL_SITE_ID ""
        write_env_line CENTRAL_PUSH_SECRET ""

        write_env_line ENABLE_DB_BACKUPS "$ENABLE_DB_BACKUPS"
        write_env_line BACKUP_RETENTION_DAYS "$BACKUP_RETENTION_DAYS"
        write_env_line PORTAL_ADMIN_USER "$PORTAL_ADMIN_USER"
        write_env_line PORTAL_ADMIN_PASSWORD "$PORTAL_ADMIN_PASSWORD"
    } > "$ENV_TMP"
}

# =============================================================================
# Pi networkd and repo configuration
# =============================================================================

configure_pi_networkd() {
    info "Configuring Pi systemd-networkd VLAN interfaces"

    local tmpdir
    tmpdir="$(mktemp -d)"

    local all_pi_vlans=("${VLAN_LIST[@]}" "$MANAGEMENT_VLAN" "$WIRED_VLAN")

    {
        echo "[Match]"
        echo "Name=eth0"
        echo
        echo "[Network]"
        for vlan in "${all_pi_vlans[@]}"; do
            echo "VLAN=eth0.$vlan"
        done
    } > "$tmpdir/10-eth0.network"

    for vlan in "${all_pi_vlans[@]}"; do
        cat > "$tmpdir/11-eth0.$vlan.netdev" <<EOF
[NetDev]
Name=eth0.$vlan
Kind=vlan

[VLAN]
Id=$vlan
EOF

        cat > "$tmpdir/21-eth0.$vlan.network" <<EOF
[Match]
Name=eth0.$vlan

[Network]
Address=${LOCAL_BASE}.${vlan}.${PORTAL_IP_BYTE}/24
EOF

        if [ "$vlan" = "$MANAGEMENT_VLAN" ]; then
            cat >> "$tmpdir/21-eth0.$vlan.network" <<EOF
MACVLAN=macvlan-dns
EOF
        fi
    done

    cat > "$tmpdir/45-macvlan-dns.netdev" <<EOF
[NetDev]
Name=macvlan-dns
Kind=macvlan

[MACVLAN]
Mode=bridge
EOF

    cat > "$tmpdir/55-macvlan-dns.network" <<EOF
[Match]
Name=macvlan-dns

[Network]
Address=${HIJACK_DNS_IP}/32
LinkLocalAddressing=no
EOF

    cat > "$tmpdir/99-unmanaged-eth0.conf" <<EOF
[keyfile]
unmanaged-devices=interface-name:eth0;interface-name:eth0.*
EOF

    pi_sudo "mkdir -p /etc/systemd/network /etc/NetworkManager/conf.d"
    pi_sudo "rm -f /etc/systemd/network/10-eth0.network /etc/systemd/network/11-eth0.*.netdev /etc/systemd/network/21-eth0.*.network /etc/systemd/network/45-macvlan-dns.netdev /etc/systemd/network/55-macvlan-dns.network"

    for file in "$tmpdir"/*; do
        local base
        base="$(basename "$file")"
        echo "Copying $file in $tmpdir to Pi... /tmp/$base "
        pi_scp_to "$file" "/tmp/$base"
        case "$base" in
            99-unmanaged-eth0.conf)
                pi_sudo "mv /tmp/$base /etc/NetworkManager/conf.d/$base"
                ;;
            *)
                pi_sudo "mv /tmp/$base /etc/systemd/network/$base"
                ;;
        esac
    done

    pi_sudo "find /etc/systemd/network -type f -exec chown root:root {} +"
    pi_sudo "find /etc/systemd/network -type f -exec chmod 644 {} +"

    pi_sudo "if [ -f /etc/dhcpcd.conf ] && ! grep -q \"denyinterfaces eth0\" /etc/dhcpcd.conf; then
        printf \"\n# bf-network: eth0 is managed by systemd-networkd\n\" >> /etc/dhcpcd.conf
        printf \"denyinterfaces eth0 eth0.*\n\" >> /etc/dhcpcd.conf  
    fi"
    pi_sudo "systemctl enable systemd-networkd"
    pi_sudo "systemctl restart systemd-networkd || true"
    pi_sudo "systemctl restart NetworkManager || true"
    pi_sudo "systemctl restart dhcpcd || true"
}

patch_repo_for_install() {
    info "Patching bf-network repository for this Pi user and generated values"

    local q_repo
    q_repo="$(shell_quote "$PI_REPO_DIR")"

    info "1"

    pi_sudo "set -x; cd $q_repo && sed -i 's#/home/admin/.ssh:/keys:ro#/home/$PI_USER/.ssh:/keys:ro#g' docker-compose.yml"
    info "2"
    pi_sudo "set -x; cd $q_repo && sed -i \"s|SWITCH_KEY_PATH: /keys/id_rsa|SWITCH_KEY_PATH: \\\${SWITCH_KEY_PATH:-/keys/id_rsa}|g\" docker-compose.yml"
    info "3"
    pi_sudo "set -x; cd $q_repo && sed -i \"s|WATCHDOG_SWITCH_KEY_PATH: /keys/id_rsa|WATCHDOG_SWITCH_KEY_PATH: \\\${SWITCH_KEY_PATH:-/keys/id_rsa}|g\" docker-compose.yml"
    info "4"
    pi_sudo "set -x; cd $q_repo && sed -i \"s|WATCHDOG_PEER_SSH_KEY: /keys/id_rsa|WATCHDOG_PEER_SSH_KEY: \\\${SWITCH_KEY_PATH:-/keys/id_rsa}|g\" docker-compose.yml"
    info "5"

    # The tunnel entrypoint in the repository defaults to /keys/oracle_rsa and fixed reverse ports.
    # This installer intentionally uses the same mounted key path as switch automation and the
    # remote HTTPS tunnel port entered above.

    # Patch the reverse-tunnel entrypoint so the Pi opens the selected VPS
    # local HTTPS port, instead of any repository default such as 9443. Do this
    # with a copied Python script rather than nested sed inside pi_sudo; the
    # latter is too fragile because pi_sudo already wraps the command in bash -lc.
    local tmp_tunnel_patch
    tmp_tunnel_patch="$(mktemp)"
    cat > "$tmp_tunnel_patch" <<'PYEOF'
#!/usr/bin/env python3
import re
import sys
from pathlib import Path

repo_dir, key_path, port = sys.argv[1:4]
path = Path(repo_dir) / "captive-portal" / "tunnel-entrypoint.sh"

if not path.exists():
    print(f"tunnel patch: {path} does not exist; skipping")
    raise SystemExit(0)

text = path.read_text()
text = text.replace("/keys/oracle_rsa", key_path)
text = text.replace("127.0.0.1:9443:localhost:443", f"127.0.0.1:{port}:localhost:443")
text = text.replace("-R 9443:localhost:443", f"-R {port}:localhost:443")
text = re.sub(r"(?<![0-9])9443:localhost:443", f"{port}:localhost:443", text)
path.write_text(text)
print(f"tunnel patch: updated {path} for reverse HTTPS port {port}")
PYEOF
    pi_scp_to "$tmp_tunnel_patch" "/tmp/bf-patch-tunnel.py"
    rm -f "$tmp_tunnel_patch"
    pi_sudo "python3 /tmp/bf-patch-tunnel.py $q_repo $(shell_quote "$ORACLE_VPS_SSH_KEY_PATH") $(shell_quote "$ORACLE_VPS_HTTPS_PORT") && rm -f /tmp/bf-patch-tunnel.py"

    # Make NPM fully automatic and allow npm-setup to read the DNS-01 certificate
    # issued under ./npm/letsencrypt. Copy a small patcher to the Pi instead of
    # embedding Python inside the remote sudo shell command.
    local tmp_compose_patch
    tmp_compose_patch="$(mktemp)"
    cat > "$tmp_compose_patch" <<'PYEOF'
#!/usr/bin/env python3
from pathlib import Path

path = Path('docker-compose.yml')
text = path.read_text()

npm_marker = '  npm:\n    image: jc21/nginx-proxy-manager:latest\n'
if npm_marker in text and 'INITIAL_ADMIN_EMAIL: ${NPM_ADMIN_EMAIL}' not in text:
    text = text.replace(
        npm_marker,
        npm_marker + '    environment:\n'
                     '      INITIAL_ADMIN_EMAIL: ${NPM_ADMIN_EMAIL}\n'
                     '      INITIAL_ADMIN_PASSWORD: ${NPM_ADMIN_PASSWORD}\n',
        1,
    )

setup_volume = '      - ./npm/setup.py:/setup.py:ro\n'
if setup_volume in text and '      - ./npm/letsencrypt:/etc/letsencrypt:ro\n' not in text:
    text = text.replace(
        setup_volume,
        setup_volume + '      - ./npm/letsencrypt:/etc/letsencrypt:ro\n',
        1,
    )

path.write_text(text)
print('compose patch: updated docker-compose.yml for automatic NPM setup')
PYEOF
    pi_scp_to "$tmp_compose_patch" "/tmp/bf-patch-compose.py"
    rm -f "$tmp_compose_patch"
    pi_sudo "cd $q_repo && python3 /tmp/bf-patch-compose.py && rm -f /tmp/bf-patch-compose.py"

    # Make Kea lease timers configurable from .env if the generator still has the older constants.
    pi_sudo "cd $q_repo && cat > /tmp/fix-kea.sed << 'SEOF'
s/\"renew-timer\": 300,/\"renew-timer\": int(os.environ.get(\"KEA_RENEW_TIMER\", \"300\")),/
s/\"rebind-timer\": 480,/\"rebind-timer\": int(os.environ.get(\"KEA_REBIND_TIMER\", \"480\")),/
s/\"valid-lifetime\": 600,/\"valid-lifetime\": int(os.environ.get(\"KEA_VALID_LIFETIME\", \"600\")),/
SEOF
sed -i -f /tmp/fix-kea.sed scripts/generate-kea-config.py
rm -f /tmp/fix-kea.sed"
    info "6"
}

install_fixed_npm_setup_py() {
    info "Using repository npm/setup.py"

    local q_repo
    q_repo="$(shell_quote "$PI_REPO_DIR")"

    
    pi_sudo "cd $q_repo && test -f npm/setup.py" \
        || die "Repository npm/setup.py not found; clone the repo first."
    
    # Optional sanity check and permissions.
    pi_sudo "cd $q_repo && python3 -m py_compile npm/setup.py"
    
    pi_sudo "cd $q_repo && chmod 755 npm/setup.py && chown $PI_USER:$PI_USER npm/setup.py"
    
    pi_sudo "cd $q_repo && docker compose run --rm npm-setup"
    
    pi_sudo "cd $q_repo && docker compose restart npm"
    
}

wipe_pi_docker_data() {
    local q_repo
    q_repo="$(shell_quote "$PI_REPO_DIR")"

    info "Wiping bf-network Docker containers and volumes on the Pi (clean DB)"

    # Stop and remove containers, networks, and named volumes declared in compose
    pi_sudo "cd $q_repo && if docker compose version >/dev/null 2>&1; then
        docker compose down --remove-orphans -v || true
      else
        docker-compose down --remove-orphans -v || true
      fi"

    # Project-named volumes sometimes remain; remove any that still match the project
    pi_sudo "cd $q_repo && project=\$(basename \"$PI_REPO_DIR\" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
      docker volume ls -q | while read -r vol; do
        case \"\$vol\" in
          \${project}_*|bf-network_*|*captive*|*postgres*|*pihole*)
            echo \"Removing volume: \$vol\"
            docker volume rm -f \"\$vol\" 2>/dev/null || true
            ;;
        esac
      done"

    # Bind-mounted state that can reintroduce old data (adjust paths if your compose differs)
    pi_sudo "cd $q_repo && rm -rf \
        kea/leases/* \
        kea/sockets/* \
        captive-portal/redis-data/* \
        npm/data/* \
        pihole/etc-pihole/* \
        pihole/etc-dnsmasq.d/* \
        2>/dev/null || true"

    echo "Docker volumes and local bind-mount data cleared."
}
seed_isp_routers() {
    local q_repo="$1"

    info "Seeding isp_routers and VLAN → ISP mappings"

    # --- Rebuild ISP_SWITCH_* from state if this process did not run the switch loop ---
    local i
    for i in "${!ISP_NAMES[@]}"; do
        if [ -z "${ISP_SWITCH_HOST[$i]:-}" ] && answer_exists "isp_${i}_switch_host"; then
            ISP_SWITCH_HOST[$i]="${SAVED_ANSWERS[isp_${i}_switch_host]}"
        fi
        if [ -z "${ISP_SWITCH_PORT[$i]:-}" ] && answer_exists "isp_${i}_switch_port"; then
            ISP_SWITCH_PORT[$i]="${SAVED_ANSWERS[isp_${i}_switch_port]}"
        fi
    done

    # --- Rebuild VLAN → ISP index from vlan_${vlan}_isp answers ---
    declare -A VLAN_ISP_INDEX=()
    local vlan ans idx
    for vlan in "${VLAN_LIST[@]}"; do
        ans="${SAVED_ANSWERS[vlan_${vlan}_isp]:-}"
        if ! [[ "$ans" =~ ^[0-9]+$ ]] || [ "$ans" -lt 1 ] || [ "$ans" -gt "${#ISP_NAMES[@]}" ]; then
            die "Missing/invalid ISP choice for VLAN $vlan (expected key vlan_${vlan}_isp)"
        fi
        VLAN_ISP_INDEX[$vlan]=$((ans - 1))
    done

    local sql name subnet vlan_id switch_host switch_port isp_name
    sql="$(mktemp)"
    {
        echo "BEGIN;"

        for i in "${!ISP_NAMES[@]}"; do
            name="${ISP_NAMES[$i]}"
            subnet="${ISP_NETWORK_PORTION[$i]}.0/24"
            vlan_id=$((i + 1))
            switch_host="${ISP_SWITCH_HOST[$i]:-}"
            switch_port="${ISP_SWITCH_PORT[$i]:-}"
            gateway_ip="${ISP_GW[$i]:-}"

            # Upsert by unique name — no DELETE needed
            printf "INSERT INTO isp_routers (
  name, subnet, vlan_id, gateway_ip, switch_port, switch_host,
  dhcp_snooping_trust, nat_logger_type, created_at
) VALUES (
  %s, %s, %s, %s, %s, %s,
  TRUE, 'none', NOW()
)
ON CONFLICT (name) DO UPDATE SET
  subnet      = EXCLUDED.subnet,
  vlan_id     = EXCLUDED.vlan_id,
  gateway_ip  = EXCLUDED.gateway_ip,
  switch_port = EXCLUDED.switch_port,
  switch_host = EXCLUDED.switch_host;\n" \
    "$(sql_quote "$name")" \
    "$(sql_quote "$subnet")" \
    "$vlan_id" \
    "$(sql_quote "$gateway_ip")" \
    "$(sql_quote_or_null "$switch_port")" \
    "$(sql_quote_or_null "$switch_host")"
        done

        for vlan in "${VLAN_LIST[@]}"; do
            idx="${VLAN_ISP_INDEX[$vlan]}"
            isp_name="${ISP_NAMES[$idx]}"
            # Only updates rows that already exist (created by init-db / app)
            printf "UPDATE vlan_mappings
SET isp_router_id = (SELECT id FROM isp_routers WHERE name = %s)
WHERE vlan_id = %s;\n" \
                "$(sql_quote "$isp_name")" \
                "$vlan"
        done

        echo "COMMIT;"
    } > "$sql"

    # Debug (optional): show what will run
    echo "--- seed_isp_routers.sql ---"
    cat "$sql"
    echo "----------------------------"

    pi_scp_to "$sql" /tmp/seed_isp_routers.sql
    pi_sudo "cd $q_repo && \
      docker cp /tmp/seed_isp_routers.sql captive-portal-db:/tmp/seed_isp_routers.sql && \
      docker compose exec -T db \
        psql -U portal_user -d captive_portal -v ON_ERROR_STOP=1 -f /tmp/seed_isp_routers.sql && \
      docker compose exec -T db rm -f /tmp/seed_isp_routers.sql && \
      rm -f /tmp/seed_isp_routers.sql"

    rm -f "$sql"
}

sql_quote() {
    # single-quote for SQL literals
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

sql_quote_or_null() {
    if [ -z "${1:-}" ]; then
        printf 'NULL'
    else
        sql_quote "$1"
    fi
}

configure_pi_backups() {
    if ! is_yes "$ENABLE_DB_BACKUPS"; then
        return 0
    fi

    info "Installing simple PostgreSQL backup cron job on Pi"

    local tmpdir
    tmpdir="$(mktemp -d)"
    cat > "$tmpdir/bf-network-db-backup.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
REPO_DIR="${BF_NETWORK_REPO_DIR:-/home/admin/bf-network}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
ENV_FILE="$REPO_DIR/.env"
BACKUP_DIR="$REPO_DIR/backups/postgres"
[ -f "$ENV_FILE" ] || exit 0
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
if docker ps --format '{{.Names}}' | grep -qx 'captive-portal-db'; then
    docker exec captive-portal-db pg_dump -U "${DB_USER:-portal_user}" "${DB_NAME:-captive_portal}" | gzip > "$BACKUP_DIR/db-$STAMP.sql.gz"
    find "$BACKUP_DIR" -type f -name 'db-*.sql.gz' -mtime +"$RETENTION_DAYS" -delete
fi
EOF

    pi_scp_to "$tmpdir/bf-network-db-backup.sh" "/tmp/bf-network-db-backup.sh"
    pi_sudo "mv /tmp/bf-network-db-backup.sh /usr/local/sbin/bf-network-db-backup && chmod 755 /usr/local/sbin/bf-network-db-backup"
    pi_sudo "printf 'BF_NETWORK_REPO_DIR=%s\nBACKUP_RETENTION_DAYS=%s\n' $(shell_quote "$PI_REPO_DIR") $(shell_quote "$BACKUP_RETENTION_DAYS") > /etc/bf-network-backup.env"
    pi_sudo "cat > /etc/cron.d/bf-network-db-backup <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 3 * * * root set -a; . /etc/bf-network-backup.env; set +a; /usr/local/sbin/bf-network-db-backup >/var/log/bf-network-db-backup.log 2>&1
EOF"
}

# ---------------------------------------------------------------------------
# Kea PostgreSQL schema (must match the Kea version in kea/Dockerfile)
# ---------------------------------------------------------------------------
reset_kea_schema() {
    local q_repo
    q_repo="$(shell_quote "$PI_REPO_DIR")"

    info "Stopping services that may hold DB connections"
    pi_sudo "cd $q_repo && docker compose stop npm web kea redis freeradius dns-parser dnsmasq-hijack nat-parser pihole tunnel rsyslog watchdog npm-setup || true"

    info "Ensuring db is up for schema reset"
    pi_sudo "cd $q_repo && docker compose up -d db"

    info "Terminating any remaining captive_portal sessions"
    pi_sudo "cd $q_repo && docker compose exec -T db psql -U portal_user -d captive_portal -v ON_ERROR_STOP=1 -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid();\""

    info "Dropping and recreating public schema"
    pi_sudo "cd $q_repo && docker compose exec -T db psql -U portal_user -d captive_portal -v ON_ERROR_STOP=1 -c \"DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO portal_user;\""
}
apply_portal_schema() {
    local q_repo sql_rel
    q_repo="$(shell_quote "$PI_REPO_DIR")"

    info "Ensuring portal PostgreSQL schema is present"

    sql_rel="$(pi_ssh "cd $q_repo && for f in \
        init-db.sql \
        web/init-db.sql \
        captive-portal/init-db.sql \
        app/init-db.sql \
        db/init-db.sql; do
            [ -f \"\$f\" ] && { printf '%s' \"\$f\"; break; }
        done")"

    if [ -z "$sql_rel" ]; then
        die "Could not find a portal init-db.sql file in the repository."
    fi

    info "Applying portal schema from $sql_rel"

    pi_sudo "cd $q_repo && docker cp $sql_rel captive-portal-db:/tmp/init-db.sql"

    if ! pi_sudo "cd $q_repo && docker compose exec -T db psql -U portal_user -d captive_portal -v ON_ERROR_STOP=1 -f /tmp/init-db.sql"; then
        pi_sudo "cd $q_repo && docker compose exec -T db rm -f /tmp/init-db.sql"
        die "Portal schema apply failed."
    fi

    pi_sudo "cd $q_repo && docker compose exec -T db rm -f /tmp/init-db.sql"
    echo "Portal schema applied successfully."
}

apply_kea_schema() {
    local q_repo="$1"
    local expected_version="29.0"

    info "Ensuring Kea PostgreSQL schema is present"

    local found
    found=$(pi_ssh "cd $q_repo && docker compose exec -T db psql -U portal_user -d captive_portal -tAc \"SELECT version || '.' || COALESCE(minor, 0) FROM schema_version LIMIT 1\" 2>/dev/null | tr -d '[:space:]'")

    if [ "$found" = "$expected_version" ]; then
        echo "Kea schema already at $expected_version — skipping."
        return 0
    fi

    if [ -n "$found" ]; then
        echo "Kea schema version is '$found' (expected $expected_version) — recreating."
    else
        echo "Kea schema missing or incomplete — creating."
    fi

    # Kea must not be using the database while the schema is being recreated.
    pi_sudo "cd $q_repo && docker compose stop kea >/dev/null 2>&1 || true"

    # Single-line DROP — avoids multi-line quoting failures
    reset_kea_schema
    apply_portal_schema

    pi_sudo "cd $q_repo && docker cp kea/dhcpdb_create.pgsql captive-portal-db:/tmp/dhcpdb_create.pgsql"

    
    if ! pi_sudo "cd $q_repo && docker compose exec -T db psql -U portal_user -d captive_portal -v ON_ERROR_STOP=1 -f /tmp/dhcpdb_create.pgsql"; then
        pi_sudo "cd $q_repo && docker compose exec -T db rm -f /tmp/dhcpdb_create.pgsql"
        die "Kea schema apply failed (psql returned an error)."
    fi

    

    pi_sudo "cd $q_repo && docker compose exec -T db rm -f /tmp/dhcpdb_create.pgsql"
    echo "Kea schema applied successfully."
}

normalize_unifi_system_properties() {
    # Prefer explicit path; fall back if caller left unifi_dir in the environment
    local dir="${1:-${unifi_dir:-/home/${PI_USER}/unifi}}"
    local q_dir q_user
    q_dir="$(shell_quote "$dir")"
    q_user="$(shell_quote "$PI_USER")"

    # pi_sudo already runs: sudo bash -lc '<this string>'
    pi_sudo "for f in $q_dir/data/system.properties $q_dir/data/data/system.properties; do
  [ -f \"\$f\" ] || continue
  sed -i -e '/^unifi\\.http\\.port=/d' -e '/^unifi\\.https\\.port=/d' \"\$f\"
done
chown -R $q_user:$q_user $q_dir
[ -d $q_dir/data ] && chmod -R u+rwX $q_dir/data"
}

install_unifi_controller() {
    if ! is_yes "${INSTALL_UNIFI_CONTROLLER:-y}"; then
        echo "Skipping UniFi controller (INSTALL_UNIFI_CONTROLLER is not yes)."
        return 0
    fi

    # Ensure FQDN / port are set (prompts already ran earlier)
    UNIFI_FORWARD_PORT="${UNIFI_FORWARD_PORT:-8080}"
    UNIFI_FQDN="${UNIFI_FQDN:-${UNIFI_SUBDOMAIN}.${MAIN_DOMAIN}}"
    ORACLE_VPS_UNIFI_HTTPS_PORT="${ORACLE_VPS_UNIFI_HTTPS_PORT:-9446}"

    local unifi_dir="/home/${PI_USER}/unifi"
    local q_unifi q_user
    q_unifi="$(shell_quote "$unifi_dir")"
    q_user="$(shell_quote "$PI_USER")"

    info "Clean UniFi install under $unifi_dir (existing controller data will be removed)"

    # Stop anything already running under this compose project
    pi_sudo "if [ -f $q_unifi/docker-compose.yml ]; then cd $q_unifi && (docker compose down --remove-orphans 2>/dev/null || docker-compose down --remove-orphans 2>/dev/null || true); fi"
    pi_sudo "docker rm -f unifi unifi-tunnel 2>/dev/null || true"
    pi_sudo "rm -rf $q_unifi/data"
    pi_sudo "mkdir -p $q_unifi/data && chown -R $q_user:$q_user $q_unifi && chmod 755 $q_unifi $q_unifi/data"

    info "Installing UniFi controller under $unifi_dir"

    # --- Pi: directory + compose (8081 inform, 8444 UI; avoids portal :8080) ---
    pi_sudo "mkdir -p $q_unifi/data && chown -R $q_user:$q_user $q_unifi"

    

    local tmp_compose
    tmp_compose="$(mktemp)"
    cat > "$tmp_compose" <<EOF
services:
  unifi:
    image: jacobalberty/unifi:latest
    container_name: unifi
    restart: unless-stopped
    volumes:
      - ./data:/unifi
    environment:
      TZ: Europe/London
      LOTSOFDEVICES: "true"
    ports:
      - "${UNIFI_FORWARD_PORT}:8080"
      - "8444:8443"
      - "3478:3478/udp"
      - "10001:10001/udp"
      - "8843:8843"
      - "8880:8880"
      - "6789:6789"

  unifi-tunnel:
    image: alpine:latest
    container_name: unifi-tunnel
    restart: unless-stopped
    network_mode: host
    depends_on:
      - unifi
    environment:
      ORACLE_VPS_HOST: ${ORACLE_VPS_HOST}
      ORACLE_VPS_USER: ${ORACLE_VPS_USER:-ubuntu}
      ORACLE_VPS_UNIFI_HTTPS_PORT: ${ORACLE_VPS_UNIFI_HTTPS_PORT:-9446}
      ORACLE_VPS_SSH_KEY_PATH: ${ORACLE_VPS_SSH_KEY_PATH:-/keys/oracle_rsa}
    volumes:
      - /home/${PI_USER}/.ssh:/keys:ro
      - ./unifi-tunnel-entrypoint.sh:/tunnel-entrypoint.sh:ro
      - /etc/localtime:/etc/localtime:ro
    entrypoint: ["/tunnel-entrypoint.sh"]
EOF
    # Fix SSH key mount user path for this install
    sed -i "s|/home/admin/.ssh|/home/${PI_USER}/.ssh|" "$tmp_compose"

    pi_scp_to "$tmp_compose" "/tmp/unifi-docker-compose.yml"
    rm -f "$tmp_compose"
    pi_sudo "mv /tmp/unifi-docker-compose.yml $q_unifi/docker-compose.yml && chown $q_user:$q_user $q_unifi/docker-compose.yml"

    # --- Pi: tunnel entrypoint (second reverse port → UniFi UI :8444) ---
    local tmp_tun
    tmp_tun="$(mktemp)"
    cat > "$tmp_tun" <<'EOF'
#!/bin/sh
set -e
apk add --no-cache openssh-client autossh >/dev/null
exec autossh -M 0 -N \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -i "${ORACLE_VPS_SSH_KEY_PATH:-/keys/oracle_rsa}" \
  -R "127.0.0.1:${ORACLE_VPS_UNIFI_HTTPS_PORT}:127.0.0.1:8444" \
  "${ORACLE_VPS_USER:-ubuntu}@${ORACLE_VPS_HOST}"
EOF
    pi_scp_to "$tmp_tun" "/tmp/unifi-tunnel-entrypoint.sh"
    rm -f "$tmp_tun"
    pi_sudo "mv /tmp/unifi-tunnel-entrypoint.sh $q_unifi/unifi-tunnel-entrypoint.sh && chmod 755 $q_unifi/unifi-tunnel-entrypoint.sh && chown $q_user:$q_user $q_unifi/unifi-tunnel-entrypoint.sh"

    # --- Pi: .env for compose ---
    pi_sudo "cat > $q_unifi/.env <<EOF
ORACLE_VPS_HOST=${ORACLE_VPS_HOST}
ORACLE_VPS_USER=${ORACLE_VPS_USER}
ORACLE_VPS_UNIFI_HTTPS_PORT=${ORACLE_VPS_UNIFI_HTTPS_PORT}
ORACLE_VPS_SSH_KEY_PATH=/keys/oracle_rsa
EOF
chown $q_user:$q_user $q_unifi/.env"

    # Copy oracle key into Pi user .ssh if missing (same key portal tunnel uses)
    pi_sudo "mkdir -p /home/${PI_USER}/.ssh && chmod 700 /home/${PI_USER}/.ssh"
    if [ -f "$ORACLE_KEY_PATH" ]; then
        pi_scp_to "$ORACLE_KEY_PATH" "/tmp/oracle_rsa"
        pi_sudo "mv /tmp/oracle_rsa /home/${PI_USER}/.ssh/oracle_rsa && chmod 600 /home/${PI_USER}/.ssh/oracle_rsa && chown ${PI_USER}:${PI_USER} /home/${PI_USER}/.ssh/oracle_rsa"
    fi

    install_vps_tls_from_pi_store

    # Reload nginx with SSL server block
    oracle_update_oracle_vps_nginx "$UNIFI_FQDN" "https" "$ORACLE_VPS_UNIFI_HTTPS_PORT" "$MAIN_DOMAIN"


    normalize_unifi_system_properties "$unifi_dir"
    # --- Pi: start UniFi + tunnel ---
    pi_sudo "cd $q_unifi && if docker compose version >/dev/null 2>&1; then docker compose up -d; else docker-compose up -d; fi"

    
    info "Waiting for UniFi HTTPS on :8444"
    if ! pi_sudo 'for i in $(seq 1 24); do code=$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8444/ 2>/dev/null || echo 000); if [ "$code" = "200" ] || [ "$code" = "302" ]; then echo "UniFi UI ready (HTTP $code)"; exit 0; fi; echo "  try $i: $code"; sleep 5; done; exit 1'; then
        echo "UniFi not answering on :8444 — stripping host ports and restarting..."
        normalize_unifi_system_properties "$unifi_dir"
        pi_sudo "cd $q_unifi && docker compose restart unifi"
        pi_sudo 'for i in $(seq 1 24); do code=$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8444/ 2>/dev/null || echo 000); if [ "$code" = "200" ] || [ "$code" = "302" ]; then echo "UniFi UI ready after repair (HTTP $code)"; exit 0; fi; sleep 5; done; echo "WARNING: UniFi still not ready on :8444" >&2; exit 0'
    fi
    local unifi_dir="/home/${PI_USER}/unifi"
    local q_unifi system_ip
    q_unifi="$(shell_quote "$unifi_dir")"
    system_ip="${PORTAL_IP}"   # e.g. 10.6.99.4 — same as management / inform target

    info "Setting UniFi system_ip=${system_ip} (device inform host override)"

    

    local unifi_dir="/home/${PI_USER}/unifi"
    local q_unifi
    q_unifi="$(shell_quote "$unifi_dir")"

    # Container may own data/data — fix ownership first
    pi_sudo "mkdir -p $q_unifi/data $q_unifi/data/data"
    pi_sudo "chown -R $PI_USER:$PI_USER $q_unifi/data || true"

    # Strip any old system_ip, then append (both property files UniFi may use)
    pi_sudo "touch $q_unifi/data/system.properties"
    pi_sudo "sed -i '/^system_ip=/d' $q_unifi/data/system.properties"
    pi_sudo "printf 'system_ip=%s' $(shell_quote "$PORTAL_IP") >> $q_unifi/data/system.properties"

    pi_sudo "touch $q_unifi/data/data/system.properties"
    pi_sudo "sed -i '/^system_ip=/d' $q_unifi/data/data/system.properties"
    pi_sudo "printf 'system_ip=%s' $(shell_quote "$PORTAL_IP") >> $q_unifi/data/data/system.properties"

    pi_sudo "chown -R $PI_USER:$PI_USER $q_unifi/data"

    pi_sudo "cd $q_unifi && if docker compose version >/dev/null 2>&1; then docker compose restart unifi; else docker-compose restart unifi; fi"

    # Optional: brief wait so inform is ready again
    pi_sudo 'for i in $(seq 1 12); do
        code=$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8444/ 2>/dev/null || echo 000)
        if [ "$code" = "200" ] || [ "$code" = "302" ]; then echo "UniFi UI ready after system_ip (HTTP $code)"; exit 0; fi
        sleep 5
    done; echo "WARNING: UniFi UI not ready after system_ip restart" >&2; exit 0'

    echo "  Device inform (LAN): http://${PORTAL_IP}:${UNIFI_FORWARD_PORT:-8080}/inform"
    

    echo
    echo "UniFi controller installed."
    echo "  UI (public):  https://${UNIFI_FQDN}"
    echo "  UI (local):   https://${PI_WIFI_IP}:8444"
    echo "  Device inform (LAN): http://${PORTAL_IP}:8081/inform"
    echo "  (use set-inform on APs; do not rely on browsing /inform)"
}



install_pi_server() {
    info "Installing bf-network on Pi server"

    local q_repo q_user
    q_repo="$(shell_quote "$PI_REPO_DIR")"
    q_user="$(shell_quote "$PI_USER")"


    if ! step_done "pi_ssh_check"; then
        echo "Testing SSH access to Pi at $PI_WIFI_IP..."
        pi_ssh "echo Pi SSH OK"
        pi_ssh "ip link show eth0 >/dev/null || { echo eth0 not found on Pi; exit 1; }"
        complete_step "pi_ssh_check"
    else
        echo "Skipping completed step: Pi SSH check"
    fi

    if ! step_done "pi_docker"; then
        echo "Checking Docker status on the Raspberry Pi..."
        if pi_sudo "command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1" >/dev/null 2>&1; then
            echo "Docker and Docker Compose are already installed and working on the Pi."
            pi_sudo "docker --version"
            pi_sudo "docker compose version"
        else
            echo "Docker or Docker Compose not working on the Pi. Installing..."
            pi_sudo "apt-get update -qq"
            pi_sudo "apt-get remove -y docker.io docker-compose || true"
            pi_sudo "curl -fsSL https://get.docker.com -o /tmp/get-docker.sh"
            pi_sudo "sh /tmp/get-docker.sh"
            pi_sudo "systemctl enable docker"
            pi_sudo "systemctl start docker"
            pi_sudo "usermod -aG docker $(shell_quote "$PI_USER") || true"
            echo "Docker installation completed."
        fi
        complete_step "pi_docker"
    else
        echo "Skipping completed step: Docker installation"
    fi

    # Clone before issuing the certificate because the certificate directory is
    # inside the repository tree. The original order deleted the certificate
    # when rm -rf was later used before git clone.


    if ! step_done "pi_repo_clone"; then
        
        info "Cloning bf-network repository on the Pi"
        pi_sudo "cd $q_repo && docker compose down --remove-orphans 2>/dev/null || true"
        pi_sudo "rm -rf $q_repo"
        pi_sudo "git clone --branch $(shell_quote "$BF_REPO_BRANCH") $(shell_quote "$BF_REPO_URL") $q_repo"
        pi_sudo "chown -R $q_user:$q_user $q_repo"
        complete_step "pi_repo_clone"
        unset 'COMPLETED_STEPS[pi_repo_patch]'
        unset 'COMPLETED_STEPS[pi_env_file]'    
        unset 'COMPLETED_STEPS[pi_compose_up]'
        state_save
    else
        echo "Skipping completed step: repository clone"
    fi

    
    pi_sudo "mkdir -p $q_repo/freeradius/raddb/mods-config/files
        # Make sure it is a file, not a directory
        if [ -d $q_repo/freeradius/raddb/mods-config/files/authorize ]; then
            rm -rf $q_repo/freeradius/raddb/mods-config/files/authorize
        fi
        printf \"%s\n\" \"# Authorize file – users are provided by the SQL module\" \
            > $q_repo/freeradius/raddb/mods-config/files/authorize
        chmod 644 $q_repo/freeradius/raddb/mods-config/files/authorize"

 

    
    # Build vlan-prefix-map.txt (all subnets /24)
    info "Creating vlan-prefix-map.txt"
    map_entries=()
    for vlan in "${VLAN_LIST[@]}" "$MANAGEMENT_VLAN" "$WIRED_VLAN"; do
        # skip empty just in case
        [ -n "$vlan" ] || continue
        map_entries+=("${vlan}:24")
    done

    # Join with commas (no trailing comma)
    VLAN_PREFIX_MAP_CONTENT=$(IFS=,; echo "${map_entries[*]}")
    pi_sudo "mkdir -p $q_repo/kea/config
    printf \"%s\n\" $(shell_quote "$VLAN_PREFIX_MAP_CONTENT") > $q_repo/kea/config/vlan-prefix-map.txt
    chmod 644 $q_repo/kea/config/vlan-prefix-map.txt"       
    

    if ! step_done "pi_oracle_key"; then
        info "Installing Oracle VPS private key on the Pi"
        pi_sudo "mkdir -p /home/$PI_USER/.ssh"
        pi_scp_to "$ORACLE_KEY_PATH" "/tmp/oracle_rsa"
        pi_sudo "mv /tmp/oracle_rsa /home/$PI_USER/.ssh/oracle_rsa \
                && chown $q_user:$q_user /home/$PI_USER/.ssh/oracle_rsa \
                && chmod 600 /home/$PI_USER/.ssh/oracle_rsa"
        complete_step "pi_oracle_key"
    else
        echo "Skipping completed step: Oracle VPS key copy"
    fi


    if ! step_done "pi_env_file"; then
        info "Writing Pi .env file"
        write_pi_env_file
        pi_scp_to "$ENV_TMP" "/tmp/bf-network.env"
        pi_sudo "mv /tmp/bf-network.env $q_repo/.env && chmod 600 $q_repo/.env && chown $q_user:$q_user $q_repo/.env"
        rm -f "$ENV_TMP"
        unset 'COMPLETED_STEPS[pi_compose_up]'
        complete_step "pi_env_file"
    else
        echo "Skipping completed step: Pi .env file"
    fi



    if ! step_done "pi_switch_key"; then
        info "Installing HP 5130 SSH key on the Pi"
        pi_sudo "mkdir -p /home/$PI_USER/.ssh"
        pi_scp_to "$KEY_PATH" "/tmp/$SWITCH_KEY_BASENAME"
        pi_scp_to "$KEY_PATH.pub" "/tmp/$SWITCH_KEY_BASENAME.pub"
        pi_sudo "mv /tmp/$SWITCH_KEY_BASENAME /home/$PI_USER/.ssh/$SWITCH_KEY_BASENAME && mv /tmp/$SWITCH_KEY_BASENAME.pub /home/$PI_USER/.ssh/$SWITCH_KEY_BASENAME.pub && chown -R $q_user:$q_user /home/$PI_USER/.ssh && chmod 700 /home/$PI_USER/.ssh && chmod 600 /home/$PI_USER/.ssh/$SWITCH_KEY_BASENAME"
        complete_step "pi_switch_key"
    else
        echo "Skipping completed step: HP 5130 SSH key copy"
    fi



    if ! step_done "pi_repo_patch"; then
        patch_repo_for_install
        unset 'COMPLETED_STEPS[pi_compose_up]'
        complete_step "pi_repo_patch"
    else
        echo "Skipping completed step: repository patch"
    fi

    # Always refresh npm/setup.py during development because it is small,
    # idempotent, and fixes both first-run admin setup and DNS-01 cert import.


    
    if ! step_done "pi_networkd"; then
        configure_pi_networkd
        unset 'COMPLETED_STEPS[pi_compose_up]'
        complete_step "pi_networkd"
    else
        echo "Skipping completed step: Pi network configuration"
    fi

    


    if ! step_done "pi_backups"; then
        configure_pi_backups
        complete_step "pi_backups"
    else
        echo "Skipping completed step: database backup setup"
    fi


    if ! step_done "pi_db_wipe"; then
        wipe_pi_docker_data
        complete_step "pi_db_wipe"
    else
        echo "Skipping completed step: Pi Docker DB wipe"
    fi

   
    
    if ! step_done "pi_compose_up"; then
        info "Starting PostgreSQL for bf-network"
        pi_sudo "cd $q_repo && if docker compose version >/dev/null 2>&1; then docker compose up -d --build db; else docker-compose up -d --build db; fi"

        info "Waiting for database to be ready"
        pi_sudo "cd $q_repo && for attempt in \$(seq 1 60); do
            if docker compose exec -T db pg_isready -U portal_user -d captive_portal >/dev/null 2>&1; then
                exit 0
            fi
            sleep 2
        done
        docker compose exec -T db pg_isready -U portal_user -d captive_portal"

        apply_kea_schema "$q_repo"

        info "Starting full bf-network Docker stack"
        pi_sudo "cd $q_repo && if docker compose version >/dev/null 2>&1; then docker compose up -d --build; else docker-compose up -d --build; fi"
        complete_step "pi_compose_up"
        state_save
    else
        echo "Skipping completed step: Docker Compose startup"
    fi

    if ! step_done "seed_isp_routers"; then
        seed_isp_routers "$q_repo"
        complete_step "seed_isp_routers"
    fi

    if ! step_done "pi_npm_setup_script"; then
        install_fixed_npm_setup_py
        complete_step "pi_npm_setup_script"
    fi

    

    ensure_dns01_certificate_ready

    # After acme.sh/Bunny writes npm/letsencrypt/live/<domain>, rerun npm-setup.
    # The first npm-setup run during docker compose up creates the admin/proxy
    # host. This second run imports the DNS-01 certificate into NPM and attaches
    # it to the proxy host so local NPM port 443 has the expected SNI certificate.
    
    if ! step_done "pi_npm_certificate_attach"; then
        info "Importing DNS-01 certificate into NPM and attaching it to the proxy host"
        pi_sudo "cd $q_repo && docker compose run --rm npm-setup && docker compose restart npm"
        complete_step "pi_npm_certificate_attach"
    fi

    if ! step_done "pi_unifi_controller"; then
        install_unifi_controller
        complete_step "pi_unifi_controller"
    else
        echo "Skipping completed step: UniFi controller"
    fi

    unset 'COMPLETED_STEPS[validate_pi_server]'
    state_save

    validate_pi_server
    
}

validate_pi_server() {
    info "Validating Pi server"

    pi_ssh "ip addr show eth0 || true"
    for vlan in "${VLAN_LIST[@]}" "$MANAGEMENT_VLAN" "$WIRED_VLAN"; do
        pi_ssh "ip addr show eth0.$vlan || true"
    done
    pi_ssh "ip addr show macvlan-dns || true"

    local q_repo
    q_repo="$(shell_quote "$PI_REPO_DIR")"
    pi_sudo "cd $q_repo && if docker compose version >/dev/null 2>&1; then docker compose config >/tmp/bf-compose-check.txt; else docker-compose config >/tmp/bf-compose-check.txt; fi && echo 'docker compose config OK'"
    pi_sudo "cd $q_repo && if docker compose version >/dev/null 2>&1; then docker compose ps; else docker-compose ps; fi"
    pi_sudo "docker logs kea --tail 50 || true"
    pi_ssh "test -f $(shell_quote "$PI_REPO_DIR/kea/config/dhcp4.json") && echo 'Kea config generated OK' || echo 'Kea config not generated yet'"

    echo
    echo "Pi server summary:"
    echo "  Portal IP:       $PORTAL_IP"
    echo "  Hijack DNS IP:   $HIJACK_DNS_IP"
    echo "  Wired gateway:   $UNREGISTERED_GW"
    echo "  Switch hosts:    $SWITCH_HOSTS"
    echo "  Pi repo:         $PI_REPO_DIR"
}

# =============================================================================
# Start main flow
# =============================================================================

echo "=========================================="
echo "   HP 5130 + Pi Server Initial Setup Wizard"
echo "=========================================="
echo

parse_args "$@"

if [ "$EUID" -ne 0 ]; then
    echo "Requesting administrator privileges..."
    exec sudo "$0" "$@"
fi

umask 077
echo "Running with root privileges..."
echo

# GnuPG is needed before any other prompts so prior answers can be restored.
install_gpg
state_init
trap state_save_on_exit EXIT

install_ipcalc
install_expect
install_xxd
install_openssl
install_sshpass

if [ ! -f "$EXPECT_SCRIPT" ]; then
    die "Could not find expect script at $EXPECT_SCRIPT. Put test-switch-temp.exp beside this script."
fi
chmod +x "$EXPECT_SCRIPT"

# Determine the real user for SSH key storage and known_hosts.
if [ -n "${SUDO_USER:-}" ]; then
    REAL_USER="$SUDO_USER"
else
    REAL_USER="$(logname 2>/dev/null || whoami)"
fi
REAL_HOME="$(eval echo "~$REAL_USER")"

# =============================================================================
# Auto-detect current subnet
# =============================================================================

info "Detecting your current network"

MAIN_INTERFACE="$(ip route | awk '/^default/ {print $5; exit}')"
[ -n "$MAIN_INTERFACE" ] || die "Could not detect default network interface."

HOST_IP="$(ip -o -f inet addr show "$MAIN_INTERFACE" | awk '{print $4; exit}')"
[ -n "$HOST_IP" ] || die "Could not detect your IP address on $MAIN_INTERFACE."

NETWORK_ADDRESS="$(ipcalc "$HOST_IP" | awk '/Network:/ {print $2; exit}')"
CURRENT_SUBNET="$HOST_IP"

echo
echo "We've detected that you are connected to the subnet: $NETWORK_ADDRESS"
echo "Interface: $MAIN_INTERFACE"
echo

# =============================================================================
# Phase 1: Physical connection
# =============================================================================

info "Phase 1: Physical Connection"
echo "1. Connect the HP 5130 switch to the $NETWORK_ADDRESS network."
echo "2. Make sure it has power."
prompt_ack "physical_connection" "Press Enter when the switch is physically connected and powered on..."

# =============================================================================
# Phase 2: Management IPs
# =============================================================================

IPS=()

echo
info "Phase 2: Choose Management IP for the Switch"
prompt_required NUM_SWITCHES "How many HP5130 switches would you like to set up"

if ! [[ "$NUM_SWITCHES" =~ ^[0-9]+$ ]] || [ "$NUM_SWITCHES" -lt 1 ]; then
    die "Number of switches must be a positive integer."
fi

prompt_line scan_network "Would you like to scan the network for used IPs? (y/n): " "scan_network"

if is_yes "$scan_network"; then
    if ! command -v nmap >/dev/null 2>&1; then
        echo "nmap is not installed (recommended for finding free IPs)."
        prompt_line install_nmap "Would you like to install nmap now? (y/n): " "install_nmap"
        if is_yes "$install_nmap"; then
            apt-get update -qq
            apt-get install -y nmap
        else
            echo "Skipping network scan. You will need to choose IPs manually."
        fi
    fi

    if command -v nmap >/dev/null 2>&1; then
        echo "Scanning the network for used IPs..."
        NETWORK="$(first_three_octets "$CURRENT_SUBNET").0/24"
        USED_IPS="$(nmap -sn "$NETWORK" 2>/dev/null | grep "Nmap scan report for" | awk '{print $NF}' | tr -d '()' || true)"

        echo "Currently used IPs on the network:"
        echo "$USED_IPS" | sort -t . -k 4 -n || true
        echo
        echo "Suggested free IPs (avoiding .1, .254, and used ones):"
        for candidate_octet in {10..50}; do
            IP="$(first_three_octets "$CURRENT_SUBNET").$candidate_octet"
            if ! echo "$USED_IPS" | grep -qx "$IP"; then
                echo "  $IP"
            fi
        done
    fi
fi



declare -a NUMBER_OF_PORTS
declare -a MAX_1GBS_PORT

for ((i=1; i<=NUM_SWITCHES; i++)); do
    idx=$((i - 1))

    prompt_required ip "Enter the management IP for switch #$i" "switch_${idx}_management_ip"
    IPS+=("$ip")

    prompt_default num_ports "Enter the number of ports for switch #$i" "52" "switch_${idx}_number_of_ports"
    NUMBER_OF_PORTS[$idx]="$num_ports"

    prompt_default max_1gbs_port "What is the maximum 1Gbps port for switch #$i" "48" "switch_${idx}_max_1g_port"
    MAX_1GBS_PORT[$idx]="$max_1gbs_port"
done

echo
for ((i=1; i<=NUM_SWITCHES; i++)); do
    idx=$((i - 1))
    echo "Switch #$i: ${IPS[$idx]} (Ports: ${NUMBER_OF_PORTS[$idx]}, Max 1Gbps Port: ${MAX_1GBS_PORT[$idx]})"
done

# =============================================================================
# VLAN setup
# =============================================================================

info "VLAN Setup"

default_vlans="10 20 30"
if ! answer_exists "vlan_input"; then
    unset 'COMPLETED_STEPS[build_vlan_prefix_map]'    
    unset 'COMPLETED_STEPS[pi_env_file]'
    unset 'COMPLETED_STEPS[pi_networkd]'
    for j in "${!IPS[@]}"; do
        unset "COMPLETED_STEPS[switch_${j}_configured]"     
    done
    state_save
fi

prompt_line vlan_input "Enter user VLAN IDs (space separated) [$default_vlans]: " "vlan_input"

if [ -z "$vlan_input" ]; then
    vlan_input="$default_vlans"
fi

read -r -a VLAN_LIST <<< "$vlan_input"

[ "${#VLAN_LIST[@]}" -gt 0 ] || die "At least one user VLAN is required."

original_input="${VLAN_LIST[*]}"
mapfile -t VLAN_LIST < <(printf "%s\n" "${VLAN_LIST[@]}" | sort -n -u)
sorted_input="${VLAN_LIST[*]}"

if [ "$original_input" != "$sorted_input" ]; then
    echo "Note: VLANs were automatically sorted and deduplicated: $sorted_input"
fi

for vlan in "${VLAN_LIST[@]}"; do
    if ! [[ "$vlan" =~ ^[0-9]+$ ]] || [ "$vlan" -lt 1 ] || [ "$vlan" -gt 254 ]; then
        die "User VLAN $vlan is invalid for this installer. Use VLAN IDs 1-254 because VLAN ID is used as the third IP octet."
    fi
done

for ((i=0; i<${#VLAN_LIST[@]}-1; i++)); do
    current="${VLAN_LIST[$i]}"
    next="${VLAN_LIST[$((i + 1))]}"
    
    if [ "$current" -ge "$next" ]; then
        die "VLAN IDs must be strictly increasing after sorting."    
    fi

    if [ "$current" -gt 90 ] || [ "$next" -gt 90 ]; then
        die "Error: All VLANs must be 90 or less."
    fi
    diff=$((next - current))
    if [ "$diff" -lt 8 ]; then
        die "Error: VLANs must be at least 8 apart. $current and $next are too close."        
    fi
done

declare -A VLAN_NAMES
for idx in "${!VLAN_LIST[@]}"; do
    vlan="${VLAN_LIST[$idx]}"
    prompt_required name "Enter name/status for VLAN $vlan" "vlan_${vlan}_name"
    VLAN_NAMES[$idx]="$name"
done

while true; do
    prompt_line LOCAL_BASE "Enter local network base (e.g. 10.5, 172.20 or 192.168): " "local_base"
    if validate_private_base "$LOCAL_BASE"; then
        break
    fi
    echo "Error: $LOCAL_BASE is not in a valid private range."
    echo "Allowed ranges: 10.0-10.255, 172.16-172.31, or 192.168"
    invalidate_answer "local_base"
done

echo "Using local network base: $LOCAL_BASE"

prompt_default MANAGEMENT_VLAN "Enter Management VLAN ID" "99"
prompt_default WIRED_VLAN "Enter Wired Guest / unregistered VLAN ID" "250"

for vlan in "${VLAN_LIST[@]}"; do
    if [ "$vlan" = "$MANAGEMENT_VLAN" ] || [ "$vlan" = "$WIRED_VLAN" ]; then
        die "VLAN_LIST should contain user VLANs only. $vlan is already used as management or wired VLAN."
    fi
done

# =============================================================================
# ISP VLANs
# =============================================================================

while true; do
    prompt_line NUM_ISPS "How many ISPs are there? (1-4): " "num_isps"
    if [[ "$NUM_ISPS" =~ ^[1-4]$ ]]; then
        break
    fi
    echo "Please enter a number between 1 and 4."
    invalidate_answer "num_isps"
done

declare -A ISP_NAMES
declare -A ISP_NETWORK_PORTION

ISP_VLAN_CONFIG=""

for ((v=1; v<=NUM_ISPS; v++)); do
    prompt_required isp_name "Enter name for ISP VLAN $v (router/ISP name)" "isp_$((v - 1))_name"
    ISP_NAMES[$((v - 1))]="$isp_name"

    if [ "$v" -eq 1 ]; then
        if answer_exists "isp_0_network_portion"; then
            CURRENT_THREE_OCTETS="${SAVED_ANSWERS[isp_0_network_portion]}"
        else
            CURRENT_THREE_OCTETS="$(first_three_octets "$CURRENT_SUBNET")"
            save_answer "isp_0_network_portion" "$CURRENT_THREE_OCTETS"
        fi
        echo "For ISP VLAN $v ($isp_name), using network portion: $CURRENT_THREE_OCTETS"
        ISP_NETWORK_PORTION[$((v - 1))]="$CURRENT_THREE_OCTETS"
    else
        prompt_required isp_network_portion "Enter ISP VLAN network portion for VLAN $v (e.g. 10.5.2 or 192.168.2)" "isp_$((v - 1))_network_portion"
        ISP_NETWORK_PORTION[$((v - 1))]="$isp_network_portion"
    fi

    ISP_VLAN_CONFIG+="
vlan $v
name $isp_name
description UPLINK-TO-$isp_name
dhcp snooping binding record
#
"
done

# Build VLAN config blocks. User VLANs + management + wired.
VLAN_CONFIG=""
for idx in "${!VLAN_LIST[@]}"; do
    vlan="${VLAN_LIST[$idx]}"
    name="${VLAN_NAMES[$idx]}"
    VLAN_CONFIG+="
vlan $vlan
name $name
dhcp snooping binding record
arp detection enable
#
"
done

VLAN_CONFIG+="
vlan $MANAGEMENT_VLAN
name management
dhcp snooping binding record
arp detection enable
#
vlan $WIRED_VLAN
name wired_unregistered
dhcp snooping binding record
arp detection enable
#
"

# ISP_NAMES[i], ISP_NETWORK_PORTION[i], uplink VLAN = i+1  (your existing model)

declare -A VLAN_ISP_INDEX=()   # vlan_id -> index into ISP_NAMES

info "VLAN → ISP routing"
for vlan in "${VLAN_LIST[@]}"; do
    echo
    echo "User VLAN $vlan — which ISP should carry this VLAN’s traffic?"
    for i in $(printf '%s\n' "${!ISP_NAMES[@]}" | sort -n); do
        echo "  $((i + 1))) ${ISP_NAMES[$i]}  (uplink VLAN $((i + 1)), net ${ISP_NETWORK_PORTION[$i]}.0/24)"
    done
    while true; do
        prompt_line ans "Enter ISP number [1-${#ISP_NAMES[@]}]: " "vlan_${vlan}_isp"
        if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le "${#ISP_NAMES[@]}" ]; then
            VLAN_ISP_INDEX[$vlan]=$((ans - 1))
            break
        fi
        echo "Invalid choice."
        invalidate_answer "vlan_${vlan}_isp"
    done
done

declare -a ISP_GW=()
for i in $(printf '%s\n' "${!ISP_NAMES[@]}" | sort -n); do
    default_gw="${ISP_NETWORK_PORTION[$i]}.1"
    prompt_default gw \
        "Gateway IP for ISP ${ISP_NAMES[$i]} (subnet ${ISP_NETWORK_PORTION[$i]}.0/24)" \
        "$default_gw" \
        "isp_${i}_gateway"
    ISP_GW[$i]="$gw"
done

declare -a ISP_SWITCH_HOST=()
declare -a ISP_SWITCH_PORT=()

# =============================================================================
# SSH key management for HP5130 and Pi containers
# =============================================================================

SSH_DIR="$REAL_HOME/.ssh"
BASE_KEY_NAME="id_rsa_hp5130"
DEFAULT_KEY_PATH="$SSH_DIR/$BASE_KEY_NAME"

if [ ! -d "$SSH_DIR" ]; then
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chown "$REAL_USER":"$REAL_USER" "$SSH_DIR"
fi

if answer_exists "switch_key_path"; then
    KEY_PATH="${SAVED_ANSWERS[switch_key_path]}"
    if [ ! -f "$KEY_PATH" ] || [ ! -f "$KEY_PATH.pub" ]; then
        echo "Saved switch key is incomplete or missing: $KEY_PATH"
        unset 'SAVED_ANSWERS[switch_key_path]'
        unset 'COMPLETED_STEPS[switch_key_ready]'
        state_save
    fi
fi

if ! answer_exists "switch_key_path"; then
    KEY_PATH="$DEFAULT_KEY_PATH"

    if [ -f "$KEY_PATH" ] && [ -f "$KEY_PATH.pub" ]; then
        echo
        echo "A key already exists at: $KEY_PATH"
        prompt_line create_new_key "Do you want to create a NEW key instead? (y/n): " "create_new_switch_key"

        if is_yes "$create_new_key"; then
            version=1
            while true; do
                VERSIONED_KEY="id_rsa_hp5130v$(printf "%03d" "$version")"
                NEW_KEY_PATH="$SSH_DIR/$VERSIONED_KEY"
                if [ ! -e "$NEW_KEY_PATH" ] && [ ! -e "$NEW_KEY_PATH.pub" ]; then
                    KEY_PATH="$NEW_KEY_PATH"
                    break
                fi
                version=$((version + 1))
            done
            save_answer "switch_key_path" "$KEY_PATH"
            echo "Creating new key: $KEY_PATH"
            ssh-keygen -t rsa -b 2048 -f "$KEY_PATH" -N "" -C "hp5130-$(hostname)-v$(printf "%03d" "$version")"
            chown "$REAL_USER":"$REAL_USER" "$KEY_PATH" "$KEY_PATH.pub"
        else
            save_answer "switch_key_path" "$KEY_PATH"
            echo "Using existing key: $KEY_PATH"
        fi
    else
        rm -f "$KEY_PATH" "$KEY_PATH.pub"
        save_answer "switch_key_path" "$KEY_PATH"
        echo "Generating new SSH key pair for switch access..."
        ssh-keygen -t rsa -b 2048 -f "$KEY_PATH" -N "" -C "hp5130-$(hostname)"
        chown "$REAL_USER":"$REAL_USER" "$KEY_PATH" "$KEY_PATH.pub"
    fi
fi

[ -f "$KEY_PATH" ] && [ -f "$KEY_PATH.pub" ] || die "Switch SSH key pair is missing at $KEY_PATH."
if ! step_done "switch_key_ready"; then
    complete_step "switch_key_ready"
else
    echo "Using saved switch key: $KEY_PATH"
fi

PUBKEY_PEM="$(ssh-keygen -f "${KEY_PATH}.pub" -e -m pem)"
RAW_KEY="$(printf '%s\n' "$PUBKEY_PEM" | openssl pkey -pubin -inform PEM -outform DER 2>/dev/null | xxd -p -c 256 | tr -d '\n' | tr '[:lower:]' '[:upper:]')"
[ -n "$RAW_KEY" ] || die "Failed to convert public key to HP 5130 format."
PUBLIC_KEY="$(echo "$RAW_KEY" | fold -w 64)"

# =============================================================================
# Collect new switch username and Pi server setup questions
# =============================================================================

prompt_required NEW_USERNAME "Enter the NEW username for SSH access to HP5130 switches"

echo
cat <<EOF
==========================================
         PUBLIC KEY DEBUG OUTPUT
==========================================
Key path: $KEY_PATH
Key length (characters): ${#PUBLIC_KEY}

=== FULL PUBLIC KEY ===
$PUBLIC_KEY
==========================================
Public key converted to HP 5130 format successfully.
==========================================
EOF

info "Pi Server Setup"
echo "Before continuing, install Raspberry Pi OS on the Pi and make sure SSH works over WiFi."
echo "By entering the Pi password, you authorise this installer to use sudo on the Pi,"
echo "install Docker/Docker Compose, replace the bf-network repository directory,"
echo "configure /etc/systemd/network for eth0 VLANs, and reboot the Pi if required."
echo

prompt_required PI_WIFI_IP "Enter the Pi WiFi IP address"
prompt_default PI_USER "Enter the Pi SSH username" "admin"
prompt_secret_required PI_PASSWORD "Enter the Pi SSH password"
prompt_default PI_REPO_DIR "Enter bf-network install directory" "/home/$PI_USER/bf-network"
prompt_default PORTAL_IP_BYTE "Enter Pi server last octet" "4"
prompt_default HIJACK_DNS_IP_BYTE "Enter hijack DNS last octet" "5"
prompt_default ADMIN_EMAIL "Admin notification email" "robert.verrill@english.op.org"

# Ask for main domain
info "Oracle VPS Reverse Tunnel (Public Front Door)"
echo "You need one public VPS (e.g. Oracle Cloud) with Nginx installed."
echo "All domains will point to the same VPS IP."
echo

prompt_default MAIN_DOMAIN "Main domain (e.g. bf-network.duckdns.org)" "bf-network.duckdns.org"
PORTAL_URL="https://${MAIN_DOMAIN}"
CERT_STORE_DIR="/var/lib/bf-network-installer/certs/${MAIN_DOMAIN}"
CERT_REPO_DIR="${PI_REPO_DIR}/npm/letsencrypt/live/${MAIN_DOMAIN}"

prompt_default ORACLE_VPS_HTTPS_PORT \
    "Local HTTPS tunnel port on VPS - must be unique for each domain" \
    "9443" \
    "oracle_vps_https_port"

prompt_required ORACLE_VPS_HOST "Oracle VPS public IP or hostname"
DNS_ACK_KEY="oracle_dns_record_created_$(echo "$MAIN_DOMAIN" | tr '.-' '__' | tr -cd '[:alnum:]_')"

if ! answer_exists "$DNS_ACK_KEY"; then
    echo "IMPORTANT: Create DNS A record with name ${MAIN_DOMAIN} and value ${ORACLE_VPS_HOST}."
    prompt_ack "$DNS_ACK_KEY" "Press Enter after you have created this DNS record..."
else
    echo "Using saved acknowledgement: Oracle DNS A record created for this domain."
fi

prompt_default ORACLE_VPS_USER "Oracle VPS SSH username (usually ubuntu)" "ubuntu"



info "Oracle VPS SSH Key"

SAFE_DOMAIN="$(echo "$MAIN_DOMAIN" | tr '.' '_' | tr -cd '[:alnum:]_-')"
DEFAULT_ORACLE_KEY_PATH="$SSH_DIR/oracle_${SAFE_DOMAIN}"

echo "The reverse tunnel needs an SSH private key that can log into the Oracle VPS."
echo

if answer_exists "oracle_key_path"; then
    ORACLE_KEY_PATH="${SAVED_ANSWERS[oracle_key_path]}"
    if [ ! -f "$ORACLE_KEY_PATH" ]; then
        echo "Saved Oracle VPS key is missing: $ORACLE_KEY_PATH"
        unset 'SAVED_ANSWERS[oracle_key_path]'
        unset 'COMPLETED_STEPS[oracle_key_ready]'
        state_save
    fi
fi

if ! answer_exists "oracle_key_path"; then
    prompt_line has_oracle_key "Do you already have an SSH private key that works with the Oracle VPS for this domain? (y/n): " "has_oracle_key"

    if is_yes "$has_oracle_key"; then
        while true; do
            prompt_required ORACLE_KEY_PATH \
                "Enter the full path to the private key" \
                "oracle_existing_key_path"
            if [ -f "$ORACLE_KEY_PATH" ]; then
                break
            fi
            echo "File not found: $ORACLE_KEY_PATH"
            invalidate_answer "oracle_existing_key_path"
        done
        save_answer "oracle_key_path" "$ORACLE_KEY_PATH"
    else
        ORACLE_KEY_PATH="$DEFAULT_ORACLE_KEY_PATH"
        save_answer "oracle_key_path" "$ORACLE_KEY_PATH"

        if [ ! -f "$ORACLE_KEY_PATH" ]; then
            rm -f "$ORACLE_KEY_PATH.pub"
            echo "Generating a new SSH key pair for domain: $MAIN_DOMAIN"
            echo "Key will be saved as: $ORACLE_KEY_PATH"
            ssh-keygen -t rsa -b 4096 -f "$ORACLE_KEY_PATH" -N "" -C "oracle-${SAFE_DOMAIN}"
            chown "$REAL_USER":"$REAL_USER" "$ORACLE_KEY_PATH" "$ORACLE_KEY_PATH.pub"
        fi

        if ! answer_exists "oracle_public_key_installed"; then
            echo
            echo "============================================================"
            echo "  You must install the public key on the Oracle VPS"
            echo "============================================================"
            echo
            echo "Run this command:"
            echo
            echo "  ssh-copy-id -i ${ORACLE_KEY_PATH}.pub ${ORACLE_VPS_USER}@${ORACLE_VPS_HOST}"
            echo
            echo "Or manually add this public key to ~/.ssh/authorized_keys on the VPS:"
            echo
            cat "${ORACLE_KEY_PATH}.pub"
            echo
            echo "============================================================"
            prompt_ack \
                "oracle_public_key_installed" \
                "Press Enter after you have installed the public key on the Oracle VPS..."
        fi
    fi
fi

[ -f "$ORACLE_KEY_PATH" ] || die "Oracle VPS private key is missing: $ORACLE_KEY_PATH"
if ! step_done "oracle_key_ready"; then
    complete_step "oracle_key_ready"
else
    echo "Using saved Oracle VPS key: $ORACLE_KEY_PATH"
fi

ORACLE_VPS_SSH_KEY_PATH="/keys/oracle_rsa"
if ! step_done "oracle_vps_configured"; then
    configure_oracle_vps
    complete_step "oracle_vps_configured"
fi


prompt_default PORTAL_POLL_URL "Portal poll URL" "$PORTAL_URL"
prompt_default INSTITUTION_URL "Institution URL" "https://english.op.org"
prompt_default INSTITUTION_BUTTON_TEXT "Institution button text" "Visit English Province"

prompt_default PORTAL_ADMIN_USER "Initial portal admin username" "admin"
prompt_secret_required PORTAL_ADMIN_PASSWORD "Initial portal admin password"
prompt_default EMAIL_VERIFICATION_REQUIRED "Require email verification?" "false"
prompt_default VERIFICATION_TIMEOUT_MINUTES "Verification timeout minutes" "15"
prompt_default WIFI_CONFIRM_TIMEOUT_SEC "WiFi confirmation timeout seconds" "120"

info "Microsoft Graph Email"
prompt_required GRAPH_TENANT_ID "Graph tenant ID"
prompt_required GRAPH_CLIENT_ID "Graph client ID"
prompt_secret_required GRAPH_CLIENT_SECRET "Graph client secret"
prompt_required GRAPH_FROM_EMAIL "Graph from email"

info "Nginx Proxy Manager"
prompt_default NPM_ADMIN_EMAIL "NPM admin email" "admin@example.com"
prompt_secret_required NPM_ADMIN_PASSWORD "NPM admin password"

info "Bunny.net DNS-01 Certificate (for local HTTPS)"

prompt_required BUNNY_API_KEY "Bunny.net API Key (Account → API Keys)"



info "Kea / Logging / Backups"
prompt_default KEA_LEASE_LIFETIME "Kea lease lifetime seconds" "600"
prompt_default TEST_ENV "Enable TEST_ENV?" "true"
prompt_default ENABLE_DB_BACKUPS "Set up automatic database backups?" "y"
prompt_default BACKUP_RETENTION_DAYS "Backup retention days" "30"
prompt_default NAT_RETENTION_DAYS "NAT log retention days" "90"
prompt_default DNS_RETENTION_DAYS "DNS log retention days" "90"
prompt_default SWITCH_REPLUG_ENABLED "Enable automatic switch replug after wired approval?" "true"
prompt_default SWITCH_REPLUG_DELAY_SEC "Switch replug delay seconds" "3"

info "UniFi Network Controller (Docker)"
prompt_default INSTALL_UNIFI_CONTROLLER "Install UniFi controller on the Pi?" "y" "install_unifi_controller"



if is_yes "${INSTALL_UNIFI_CONTROLLER:-y}"; then
    # e.g. unifi → unifi.bf-network.duckdns.org  or  unifi.cambridge-network.english.op.org
    prompt_default UNIFI_SUBDOMAIN \
        "UniFi subdomain label (DNS name will be <label>.${MAIN_DOMAIN})" \
        "unifi" \
        "unifi_subdomain"

    UNIFI_FQDN="${UNIFI_SUBDOMAIN}.${MAIN_DOMAIN}"    

    DNS_UNIFI_KEY="oracle_dns_unifi_$(echo "$UNIFI_FQDN" | tr '.-' '__' | tr -cd '[:alnum:]_')"
    if ! answer_exists "$DNS_UNIFI_KEY"; then
        echo "IMPORTANT: Create a DNS A (or CNAME) record:"
        echo "  name:  ${UNIFI_FQDN}"
        echo "  value: ${ORACLE_VPS_HOST}"
        echo "  (same public IP as the portal VPS)"
        prompt_ack "$DNS_UNIFI_KEY" "Press Enter after the DNS record exists..."
    else
        echo "Using saved acknowledgement: DNS for ${UNIFI_FQDN}"
    fi

    pick_free_vps_tunnel_port "9446" "oracle_vps_unifi_https_port" \
        "Local HTTPS tunnel port on VPS for UniFi"
    ORACLE_VPS_UNIFI_HTTPS_PORT="$REPLY_PORT"

fi

# If UniFi is newly enabled (or subdomain changed), cert SANs are wrong
if is_yes "${INSTALL_UNIFI_CONTROLLER:-y}"; then
    if [ "${SAVED_ANSWERS[install_unifi_controller_applied]:-}" != "y:${UNIFI_FQDN:-}" ]; then
        unset 'COMPLETED_STEPS[pi_dns_certificate]'
        unset 'COMPLETED_STEPS[pi_unifi_controller]'
        state_save
        echo "Will re-issue DNS-01 cert to include ${UNIFI_FQDN:-UniFi}."
    fi
    save_answer "install_unifi_controller_applied" "y:${UNIFI_FQDN}"
else
    if [ "${SAVED_ANSWERS[install_unifi_controller_applied]:-}" != "n" ]; then
        # Optional: re-issue without UniFi SAN, or leave old SANs (harmless)
        unset 'COMPLETED_STEPS[pi_dns_certificate]'
        state_save
    fi
    save_answer "install_unifi_controller_applied" "n"
fi



derive_pi_server_values

cat <<EOF

==========================================
Derived Pi/server network settings
==========================================
NETWORK_WORD=$NETWORK_WORD
VALID_VLANS=$VALID_VLANS
VLAN_DEFAULTS=$VLAN_DEFAULTS
VLAN_PREFIX_MAP=$VLAN_PREFIX_MAP
MANAGEMENT_VLAN=$MANAGEMENT_VLAN
WIRED_VLAN=$WIRED_VLAN
PORTAL_IP=$PORTAL_IP
HIJACK_DNS_IP=$HIJACK_DNS_IP
UNREGISTERED_GW=$UNREGISTERED_GW
SWITCH_HOSTS=$SWITCH_HOSTS
SWITCH_HOSTS_BYTES=$SWITCH_HOSTS_BYTES
RADIUS_SERVER=$RADIUS_SERVER

SWITCH_KEY_PATH=$DOCKER_SWITCH_KEY_PATH
==========================================
EOF
prompt_ack "derived_settings_confirmed" "Press Enter to continue with switch configuration, then Pi installation..."

# =============================================================================
# Main switch configuration loop
# =============================================================================

m=0
echo "DEBUG: IPS indices = ${!IPS[*]}"
echo "DEBUG: IPS values  = ${IPS[*]}"



for j in "${!IPS[@]}"; do
    MGMT_IP="${IPS[$j]}"
    SWITCH_NUM=$((j + 1))
    IS_LAST_SWITCH=0
    if [ "$j" -eq $((${#IPS[@]} - 1)) ]; then
        IS_LAST_SWITCH=1
    fi


    echo
    echo "=========================================="
    echo "   Configuring Switch #$SWITCH_NUM ($MGMT_IP), j = $j"
    echo "=========================================="

    if step_done "switch_${j}_configured"; then
        echo "Switch #$SWITCH_NUM ($MGMT_IP) is already marked configured; skipping serial configuration."
        continue
    fi

        # Ask for switch name
    prompt_required SWITCH_NAME "Enter a name for this switch (e.g. AccessSW-01, CoreSW-02)" "switch_${j}_name"
    while true; do
        prompt_line KEA_PORT "Is a Kea Pi server being connected to this switch? Enter port number (1-${NUMBER_OF_PORTS[$j]}) or press Enter for none: " "switch_${j}_kea_port"

        if [ -z "$KEA_PORT" ]; then
            KEA_PORT=""
            break
        fi

        if ! [[ "$KEA_PORT" =~ ^[0-9]+$ ]]; then
            echo "Please enter a valid number or press Enter for none."
            invalidate_answer "switch_${j}_kea_port"
            continue
        fi

        if [ "$KEA_PORT" -lt 1 ] || [ "$KEA_PORT" -gt "${NUMBER_OF_PORTS[$j]}" ]; then
            echo "Port must be between 1 and ${NUMBER_OF_PORTS[$j]}."
            invalidate_answer "switch_${j}_kea_port"
            continue
        fi
        break
    done

    prompt_secret_required CURRENT_PASSWORD "Enter the CURRENT admin password for this switch" "switch_${j}_current_password"
    prompt_secret_optional NEW_ADMIN_PASSWORD "Enter NEW admin password for this switch (or press Enter to keep current)" "switch_${j}_new_admin_password"

    UPLINK_PORTS=()
    UPLINK_ISP_INDEXES=()
    uplink_prompt_index=0
    while [ $((NUM_ISPS - m)) -gt 0 ]; do
        uplink_key="switch_${j}_uplink_${uplink_prompt_index}"
        prompt_line port "Enter ISP uplink port (1-${NUMBER_OF_PORTS[$j]}) or press Enter to finish uplinks for this switch: " "$uplink_key"

        if [ -z "$port" ]; then
            if [ "$IS_LAST_SWITCH" -eq 1 ]; then
                echo "You must assign all remaining ISP uplinks on the last switch."
                invalidate_answer "$uplink_key"
                continue
            else
                break
            fi
        fi

        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt "${NUMBER_OF_PORTS[$j]}" ]; then
            echo "Invalid port. Please enter a number between 1 and ${NUMBER_OF_PORTS[$j]}."
            invalidate_answer "$uplink_key"
            continue
        fi

        if [[ " ${UPLINK_PORTS[*]} " =~ " $port " ]]; then
            echo "Port $port is already assigned as an uplink on this switch."
            invalidate_answer "$uplink_key"
            continue
        fi

        UPLINK_PORTS+=("$port")
        UPLINK_ISP_INDEXES+=("$m")

        # ISP index m is attached on this switch, this port
        LAST_OCTET="$(last_octet "$MGMT_IP")"
        # Prefer mgmt VLAN IP; last octet is what ISPRouter.switch_host_ip() uses
        ISP_SWITCH_HOST[$m]="${LOCAL_BASE}.${MANAGEMENT_VLAN}.${LAST_OCTET}"
        # or, if you insist on the installer MGMT_IP:
        # ISP_SWITCH_HOST[$m]="$MGMT_IP"

        ISP_SWITCH_PORT[$m]="$(get_interface "$port" "${MAX_1GBS_PORT[$j]}")"
        save_answer "isp_${m}_switch_host" "${ISP_SWITCH_HOST[$m]}"
        save_answer "isp_${m}_switch_port" "${ISP_SWITCH_PORT[$m]}"

        
        m=$((m + 1))
        uplink_prompt_index=$((uplink_prompt_index + 1))
    done

    INTERSWITCH_PORTS=()
    interswitch_prompt_index=0
    while true; do
        interswitch_key="switch_${j}_interswitch_${interswitch_prompt_index}"
        prompt_line port "Enter inter-switch link port (1-${NUMBER_OF_PORTS[$j]}) or press Enter to finish: " "$interswitch_key"

        if [ -z "$port" ]; then
            break
        fi

        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt "${NUMBER_OF_PORTS[$j]}" ]; then
            echo "Invalid port. Please enter a number between 1 and ${NUMBER_OF_PORTS[$j]}."
            invalidate_answer "$interswitch_key"
            continue
        fi

        if [[ " ${INTERSWITCH_PORTS[*]} " =~ " $port " ]]; then
            echo "Error: Port $port is already used as an inter-switch link on this switch."
            invalidate_answer "$interswitch_key"
            continue
        fi

        INTERSWITCH_PORTS+=("$port")
        interswitch_prompt_index=$((interswitch_prompt_index + 1))
    done

    LAST_OCTET="$(last_octet "$MGMT_IP")"

    VLAN_IFACE_CONFIG=""
    for ((v=1; v<=NUM_ISPS; v++)); do
        VLAN_IFACE_CONFIG+="
interface Vlan-interface$v
description UPLINK-TO-${ISP_NAMES[$((v - 1))]}
ip address ${ISP_NETWORK_PORTION[$((v - 1))]}.$LAST_OCTET 255.255.255.0
#
"
    done

    for vlan in "${VLAN_LIST[@]}"; do
        VLAN_IFACE_CONFIG+="
interface Vlan-interface$vlan
description GW_VLAN$vlan
ip address ${LOCAL_BASE}.${vlan}.${LAST_OCTET} 255.255.255.0
#
"
    done

    VLAN_IFACE_CONFIG+="
interface Vlan-interface$MANAGEMENT_VLAN
description GW_VLAN$MANAGEMENT_VLAN
ip address ${LOCAL_BASE}.${MANAGEMENT_VLAN}.${LAST_OCTET} 255.255.255.0
#
interface Vlan-interface$WIRED_VLAN
description GW_VLAN$WIRED_VLAN
ip address ${LOCAL_BASE}.${WIRED_VLAN}.${LAST_OCTET} 255.255.255.0
#
"

    UPLINK_CONFIG=""
    for idx in "${!UPLINK_PORTS[@]}"; do
        port="${UPLINK_PORTS[$idx]}"
        isp_index="${UPLINK_ISP_INDEXES[$idx]}"
        vlan_number=$((isp_index + 1))
        iface="$(get_interface "$port" "${MAX_1GBS_PORT[$j]}")"
        UPLINK_CONFIG+="
interface $iface
description UPLINK-TO-${ISP_NAMES[$isp_index]}
port link-type trunk
undo port trunk permit vlan 1
port trunk permit vlan $vlan_number
dhcp snooping trust
#
"
    done

    INTERSWITCH_CONFIG=""
    for port in "${INTERSWITCH_PORTS[@]}"; do
        iface="$(get_interface "$port" "${MAX_1GBS_PORT[$j]}")"
        INTERSWITCH_CONFIG+="
interface $iface
description Inter-switch link
port link-type trunk
port trunk permit vlan 1 to $NUM_ISPS ${VLAN_LIST[*]} $MANAGEMENT_VLAN $WIRED_VLAN
port trunk pvid vlan 1028
arp detection trust
dhcp snooping trust
#
"
    done

    KEA_CONFIG=""
    if [ -n "$KEA_PORT" ]; then
        iface="$(get_interface "$KEA_PORT" "${MAX_1GBS_PORT[$j]}")"
        KEA_CONFIG+="
interface $iface
description TRUNK-TO-PI-Kea
port link-type trunk
undo port trunk permit vlan 1
port trunk permit vlan ${VLAN_LIST[*]} $MANAGEMENT_VLAN $WIRED_VLAN
port trunk pvid vlan 1028
arp detection trust
dhcp snooping trust
#
"
    fi
    # VLAN-99 address for this switch (NAS-IP)
    SWITCH_NAS_IP="${LOCAL_BASE}.${MANAGEMENT_VLAN}.${LAST_OCTET}"

    RADIUS_CONFIG="
radius scheme rad1
primary authentication ${RADIUS_SERVER}
primary accounting ${RADIUS_SERVER}
key authentication simple ${RADIUS_SECRET}
key accounting simple ${RADIUS_SECRET}
user-name-format without-domain
nas-ip ${SWITCH_NAS_IP}
#
radius dynamic-author server
client ip ${RADIUS_SERVER} key simple ${RADIUS_SECRET}
#
domain macauth
authentication lan-access radius-scheme rad1
authorization lan-access radius-scheme rad1
accounting lan-access radius-scheme rad1
#
mac-authentication
mac-authentication domain macauth
#
vlan 1028
name NATIVE-NULL
#
dhcp snooping enable
"
    DEFAULT_ROUTE_CONFIG=""
    if [ "$j" -eq 0 ]; then
        DEFAULT_ROUTE_CONFIG="
ip route-static 0.0.0.0 0 ${ISP_GW[0]}
#
"
    fi

    DYNAMIC_CONFIG="$RADIUS_CONFIG$DEFAULT_ROUTE_CONFIG$ISP_VLAN_CONFIG$VLAN_IFACE_CONFIG$UPLINK_CONFIG$INTERSWITCH_CONFIG$KEA_CONFIG"

    

    if [ "$j" -eq 0 ]; then
        echo "Please plug the USB serial cable into the Pi/computer and the RJ45 end into the console port of the FIRST switch."
    else
        echo "Please move the RJ45 end of the serial cable to the console port of the NEXT switch ($MGMT_IP)."
    fi
    read -r -p "Press Enter when ready..."

    info "Phase 4: Detect Serial Port and Configure Switch #$SWITCH_NUM ($MGMT_IP)"

    if detect_switch_serial_port; then
        echo "Switch successfully detected on port: $DETECTED_PORT"
    else
        echo "Failed to detect switch on serial port. Skipping switch #$SWITCH_NUM."
        continue
    fi

    free_serial_port "$DETECTED_PORT"

    echo "Configuring switch $MGMT_IP via serial..."

    NP_ARG=()
    if [ -n "$NEW_ADMIN_PASSWORD" ]; then
        NP_ARG=(-np "$NEW_ADMIN_PASSWORD")
    fi

    # Build command as an array (safer)
    cmd=("$EXPECT_SCRIPT")
    cmd+=(-port "$DETECTED_PORT")
    cmd+=(-cp "$CURRENT_PASSWORD")
    cmd+=("${NP_ARG[@]}")
    cmd+=(-user "$NEW_USERNAME")
    cmd+=(-pubkey "$PUBLIC_KEY")
    cmd+=(-ip "$MGMT_IP")

    if [ -n "$SWITCH_NAME" ]; then
        cmd+=(-name "$SWITCH_NAME")
    else
        echo "DEBUG: SWITCH_NAME is empty"
    fi

    if [ -n "$VLAN_CONFIG" ]; then
        cmd+=(-vlan-config "$VLAN_CONFIG")
    else
        echo "DEBUG: VLAN_CONFIG is empty"
    fi

    if [ -n "$DYNAMIC_CONFIG" ]; then
        cmd+=(-dynamic-config "$DYNAMIC_CONFIG")
    else
        echo "DEBUG: DYNAMIC_CONFIG is empty"
    fi

    cmd+=(-debug)

    # Do not print the full command because it contains switch passwords.
    echo
    echo "Calling Expect script for switch $MGMT_IP on $DETECTED_PORT (password arguments redacted)."
    echo 

    echo "Command array (shell-quoted):"
    printf '  %q\n' "${cmd[@]}"

    # Execute
    "${cmd[@]}"

    echo "Switch $MGMT_IP has been configured. j=$j."
    
    complete_step "switch_${j}_configured"
done

# =============================================================================
# Pi server installation
# =============================================================================

install_pi_server


echo "All switches and the Pi server have been processed."
