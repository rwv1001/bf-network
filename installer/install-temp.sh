#!/bin/bash

set -e

echo "=========================================="
echo "   HP 5130 Initial Setup Wizard"
echo "=========================================="
echo

# Auto request sudo if not running as root
if [ "$EUID" -ne 0 ]; then
    echo "Requesting administrator privileges..."
    exec sudo "$0" "$@"
fi

echo "Running with root privileges..."
echo

# ==========================================
# Auto-install ipcalc if missing
# ==========================================
install_ipcalc() {
    if ! command -v ipcalc &> /dev/null; then
        echo "ipcalc is not installed. Installing it now..."
        sudo apt update -qq
        sudo apt install -y ipcalc

        if ! command -v ipcalc &> /dev/null; then
            echo "ERROR: Failed to install ipcalc."
            echo "Please install it manually using: sudo apt install ipcalc"
            exit 1
        fi
        echo "ipcalc installed successfully."
    fi
}


# ==========================================
# Install expect if missing
# ==========================================
install_expect() {
    if ! command -v expect &> /dev/null; then
        echo "expect is not installed. Installing now..."
        sudo apt update -qq
        sudo apt install -y expect

        if ! command -v expect &> /dev/null; then
            echo "ERROR: Failed to install expect."
            echo "Please install it manually with: sudo apt install expect"
            exit 1
        fi
        echo "expect installed successfully."
    fi
}

# ==========================================
# Install xxd if missing (needed for public key conversion)
# ==========================================
install_xxd() {
    if ! command -v xxd &> /dev/null; then
        echo "xxd is not installed. Installing now..."
        sudo apt update -qq
        sudo apt install -y xxd

        if ! command -v xxd &> /dev/null; then
            echo "ERROR: Failed to install xxd."
            echo "Please install it manually with: sudo apt install xxd"
            exit 1
        fi
        echo "xxd installed successfully."
    fi
}

install_ipcalc
install_expect
install_xxd

# ==========================================
# Auto-detect current subnet
# ==========================================
echo "Detecting your current network..."

MAIN_INTERFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
HOST_IP=$(ip -o -f inet addr show "$MAIN_INTERFACE" | awk '{print $4}' | head -1)

if [ -z "$HOST_IP" ]; then
    echo "ERROR: Could not detect your IP address."
    exit 1
fi

# Use ipcalc to get the network address (e.g. 192.168.1.0/24)
NETWORK_ADDRESS=$(ipcalc "$HOST_IP" | grep "Network:" | awk '{print $2}')

echo
echo "We've detected that you are connected to the subnet: $NETWORK_ADDRESS"
echo "Interface: $MAIN_INTERFACE"
echo

# ==========================================
# Phase 1: Physical connection
# ==========================================
echo "=== Phase 1: Physical Connection ==="
echo "1. Connect the HP 5130 switch to the $NETWORK_ADDRESS network."
echo "2. Make sure it has power."
read -p "Press Enter when the switch is physically connected and powered on..."


#==========================================
# Phase 2: Choose Management IP
# ==========================================

# ==========================================
# Determine list of switches (from args or interactive)
# ==========================================
IPS=("$@")

if [ ${#IPS[@]} -eq 0 ]; then
    echo
    echo "=== Phase 2: Choose Management IP for the Switch ==="
    echo
    echo
    read -p "How many HP5130 switches would you like to set up? " NUM_SWITCHES

        # Fix: Use HOST_IP instead of undefined CURRENT_SUBNET
    CURRENT_SUBNET="$HOST_IP"

    if ! command -v nmap &> /dev/null; then
        echo "nmap is not installed (recommended for finding free IPs)."
        read -p "Would you like to install nmap now? (y/n): " install_nmap

        if [[ "$install_nmap" == "y" ]]; then
            sudo apt update -qq
            sudo apt install -y nmap
        else
            echo "Skipping network scan. You will need to choose an IP manually."
        fi
    fi

    if command -v nmap &> /dev/null; then
        echo "Scanning the network for used IPs (this may take 10–30 seconds)..."
        echo

        NETWORK=$(echo "$CURRENT_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3).0/24

        USED_IPS=$(nmap -sn "$NETWORK" 2>/dev/null | grep "Nmap scan report for" | awk '{print $NF}' | tr -d '()')

        echo "Currently used IPs on the network:"
        echo "$USED_IPS" | sort -t . -k 4 -n
        echo

        echo "Suggested free IPs (avoiding .1, .254, and used ones):"
        for i in {10..50}; do
            IP="${NETWORK%.*}.$i"
            if ! echo "$USED_IPS" | grep -q "$IP"; then
                echo "  $IP"
            fi
        done
        echo
    fi

    for ((i=1; i<=NUM_SWITCHES; i++)); do
        read -p "Enter management IP for switch #$i: " ip
        IPS+=("$ip")
    done
else
    echo
    echo "Using provided IP addresses from command line:"
    for ip in "${IPS[@]}"; do
        echo "  - $ip"
    done
fi

# ==========================================
# SSH Key Management (done once)
# ==========================================
if [ -n "$SUDO_USER" ]; then
    REAL_USER="$SUDO_USER"
else
    REAL_USER="$(whoami)"
fi

REAL_HOME=$(eval echo ~$REAL_USER)
SSH_DIR="$REAL_HOME/.ssh"
BASE_KEY_NAME="id_rsa_hp5130"
KEY_PATH="$SSH_DIR/$BASE_KEY_NAME"

# Create .ssh directory if needed
if [ ! -d "$SSH_DIR" ]; then
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chown "$REAL_USER":"$REAL_USER" "$SSH_DIR"
fi

# Check if base key already exists
if [ -f "$KEY_PATH" ]; then
    echo
    echo "A key already exists at: $KEY_PATH"
    read -p "Do you want to create a NEW key instead? (y/n): " create_new_key

    if [[ "$create_new_key" == "y" || "$create_new_key" == "Y" ]]; then
        # Find the next available versioned key name (v001, v002, ...)
        i=1
        while true; do
            VERSIONED_KEY="id_rsa_hp5130v$(printf "%03d" $i)"
            NEW_KEY_PATH="$SSH_DIR/$VERSIONED_KEY"
            if [ ! -f "$NEW_KEY_PATH" ]; then
                KEY_PATH="$NEW_KEY_PATH"
                break
            fi
            ((i++))
        done

        echo "Creating new key: $KEY_PATH"
        ssh-keygen -t rsa -b 2048 -f "$KEY_PATH" -N "" -C "hp5130-$(hostname)-v$(printf "%03d" $i)"
        chown "$REAL_USER":"$REAL_USER" "$KEY_PATH" "$KEY_PATH.pub"
    else
        echo "Using existing key: $KEY_PATH"
    fi
else
    # No key exists yet → create the base one
    echo "Generating new SSH key pair for switch access..."
    ssh-keygen -t rsa -b 2048 -f "$KEY_PATH" -N "" -C "hp5130-$(hostname)"
    chown "$REAL_USER":"$REAL_USER" "$KEY_PATH" "$KEY_PATH.pub"
fi

# Convert OpenSSH public key to hex DER format required by HP Comware
PUBKEY_PEM=$(ssh-keygen -f "${KEY_PATH}.pub" -e -m pem)
RAW_KEY=$(
  printf '%s\n' "$PUBKEY_PEM" |
  openssl pkey -pubin -inform PEM -outform DER 2>/dev/null |
  xxd -p -c 256 |
  tr -d '\n' |
  tr '[:lower:]' '[:upper:]'
)


if [ -z "$RAW_KEY" ]; then
    echo "ERROR: Failed to convert public key to HP 5130 format."
    exit 1
fi

# Format the key with line breaks every 64 characters (even length)
PUBLIC_KEY=$(echo "$RAW_KEY" | fold -w 64)

read -p "Enter the NEW username for ssh access HP5130 switches: " NEW_USERNAME

echo
echo "=========================================="
echo "         PUBLIC KEY DEBUG OUTPUT"
echo "=========================================="
echo
echo "Key length (characters): ${#PUBLIC_KEY}"
echo
echo "=== FULL PUBLIC KEY (copy this) ==="
echo "$PUBLIC_KEY"
echo "==================================="
echo
echo "First 80 characters : ${PUBLIC_KEY:0:80}..."
echo "Last 40 characters  : ...${PUBLIC_KEY: -40}"
echo
echo "Public key converted to HP 5130 format successfully."
echo "=========================================="

detect_switch_serial_port() {
    echo "Scanning for HP 5130 switch on serial ports..."

    for port in /dev/ttyUSB{0..7}; do
        [ -e "$port" ] || continue

        echo "Testing $port ..."

        # Try up to 3 times per port
        for attempt in 1 2 3; do
            if [ $attempt -gt 1 ]; then
                echo "Retrying $port (attempt $attempt/3)..."
                sleep 5
            fi

            # Configure the serial port
            stty -F "$port" 9600 cs8 -cstopb -parenb raw -echo 2>/dev/null || continue

            # Flush any old data
            timeout 0.5 cat < "$port" > /dev/null 2>&1

            # Send two carriage returns
            echo -e "\r\r" > "$port"
            sleep 1

            # Read response
            response=$(timeout 6 cat < "$port" 2>/dev/null || true)

            echo "----------------------------------------"
            echo "Raw response from $port (attempt $attempt):"
            echo "$response"
            echo "----------------------------------------"

            # Check for typical HP switch responses
            if echo "$response" | grep -qiE 'Line aux|Automatic configuration|Login:|Password:|<|]'; then
                echo "✅ HP switch detected on: $port"
                DETECTED_PORT="$port"
                return 0
            fi
        done

        echo "No recognizable prompt found on $port after 3 attempts"
    done

    echo "❌ No HP switch detected on any serial port."
    return 1
}

# ==========================================
# Main Loop - Configure each switch
# ==========================================
for i in "${!IPS[@]}"; do
    MGMT_IP="${IPS[$i]}"
    SWITCH_NUM=$((i + 1))

    echo
    echo "=========================================="
    echo "   Configuring Switch #$SWITCH_NUM ($MGMT_IP)"
    echo "=========================================="

    if [ $i -eq 0 ]; then
        echo "Please plug the USB serial cable into the Pi and the RJ45 end into the console port of the FIRST switch."
    else
        echo "Please move the RJ45 end of the serial cable to the console port of the NEXT switch ($MGMT_IP)."
    fi
    read -p "Press Enter when ready..."

    # Ask for credentials for this switch
    read -sp "Enter the CURRENT admin password for this switch: " CURRENT_PASSWORD
    echo
    
    read -p "Enter the uplink port number (1-48): " UPLINK_PORT

    # Detect serial port
    echo "=== Phase 4: Detect Serial Port and Configure Switch ==="

    if detect_switch_serial_port; then
        echo
        echo "Switch successfully detected on port: $DETECTED_PORT"
    else    
        echo "Failed to detect switch on serial port. Skipping..."
        continue
    fi

    echo
    echo "Configuring switch $MGMT_IP via serial..."

    ./test-switch-temp.exp \
        -port "$DETECTED_PORT" \
        -cp "$CURRENT_PASSWORD" \
        -user "$NEW_USERNAME" \
        -pubkey "$PUBLIC_KEY" \
        -ip "$MGMT_IP" \
        -up "$UPLINK_PORT" \
        -debug

    echo
    echo "Switch $MGMT_IP has been configured."
done

echo
echo "All switches have been processed."