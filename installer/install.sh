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

# From here on, the script runs as root
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
echo
echo "=== Phase 2: Choose Management IP for the Switch ==="
echo

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

read -p "Enter the IP address you want to assign to the switch (e.g. 192.168.1.20): " MGMT_IP

echo
echo "You selected: $MGMT_IP"
read -p "Is this correct? (y/n): " confirm_ip

if [[ "$confirm_ip" != "y" ]]; then
    echo "Please re-run the script or enter the IP again."
    exit 1
fi

echo
echo "=== Important Notes ==="
echo
echo "1. Even though we scanned the network, it is still recommended that you"
echo "   manually verify the IP ($MGMT_IP) is not already in use."
echo
echo "2. We will find the MAC address of the switch's uplink interface shortly."
echo
echo "3. Once you have both the IP address and the MAC address, you should"
echo "   create a DHCP reservation in your DHCP server for this subnet"
echo "   ($NETWORK_ADDRESS) so the switch always gets the same IP."
echo
read -p "Press Enter to continue once you have noted the above..."

# ==========================================
# Phase 3: Collect required information
# ==========================================
echo
echo "=== Phase 3: Switch Credentials & Configuration ==="
echo

read -sp "Enter the CURRENT admin password for the switch: " CURRENT_PASSWORD
echo

read -p "Enter the NEW username you want to create on the switch: " NEW_USERNAME

read -p "Enter the uplink port number on the switch (1-48): " UPLINK_PORT

# ==========================================
# SSH Key Management for HP 5130
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

# ==========================================
# Full Debug Output - Print everything
# ==========================================
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

# ==========================================
# Phase 4: Detect serial port and configure switch
# ==========================================
echo
echo "=== Phase 4: Detect Serial Port and Configure Switch ==="


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

# Run the detection
if detect_switch_serial_port; then
    echo
    echo "Switch successfully detected on port: $DETECTED_PORT"
else
    echo "Please check your connections and try again."
    exit 1
fi

echo
echo "Now configuring the switch via serial..."

# Call the expect script
./test-switch.exp \
    -port "$DETECTED_PORT" \
    -cp "$CURRENT_PASSWORD" \
    -user "$NEW_USERNAME" \
    -pubkey "$PUBLIC_KEY" \
    -ip "$MGMT_IP" \
    -up "$UPLINK_PORT" \
    -debug

echo
echo "Switch configuration completed."
echo "You can now try to SSH into the switch using the new user and key."
echo "Please do the following on your Windows PC:"
echo
echo "1. Plug the USB serial cable into the switch console port."
echo "2. Open Device Manager → Ports (COM & LPT) and note the COM port."
echo "3. Open PowerShell and run:"
echo
echo "   Get-PnpDevice -Class Ports | Where-Object Status -eq 'OK'"
echo
read -p "Press Enter once you have identified the correct COM port..."

echo
read -p "Enter the COM port number (e.g. 5 for COM5): " COM_PORT

echo
echo "Now run this command in PowerShell:"
echo
echo "   sudo screen /dev/ttyUSBx 9600"   # (they will adapt this)
echo "   or use PuTTY with COM$COM_PORT @ 9600 baud"
echo
read -p "Press Enter when you are connected via serial and see the switch prompt..."

# Phase 4: Initial Login
echo
echo "=== Phase 4: Initial Login ==="
echo "At the switch console, do the following:"
echo
echo "1. Press Enter a few times"
echo "2. Login with: admin"
echo "3. Password: (just press Enter - default is blank)"
echo "4. Set a new password when prompted"
echo "5. Run: save force"
echo
read -p "Press Enter when you have completed the above steps..."

# Phase 5: Check interface numbering
echo
echo "=== Phase 5: Check Interface Numbering ==="
echo "Run this command on the switch:"
echo
echo "   display interface brief | include GigabitEthernet"
echo
echo "Check the interface number before /0/12"
echo "Example: If you see GigabitEthernet2/0/12, we need to change it to 1."
read -p "What number did you see before /0/12? (e.g. 1 or 2): " IF_NUM

if [[ "$IF_NUM" != "1" ]]; then
    echo
    echo "You need to change the interface numbering."
    echo "This usually requires going into the Boot ROM menu (Ctrl+B during boot)."
    echo "Would you like instructions for that? (y/n)"
    read fix_num
    if [[ "$fix_num" == "y" ]]; then
        echo "TODO: Add Boot ROM instructions here"
    fi
fi

# Phase 6: Uplink Configuration
echo
echo "=== Phase 6: Configure Uplink Port ==="
echo "Run the following commands on the switch:"
echo
echo "interface Ten-GigabitEthernet 1/0/28"     # Adjust port if needed
echo " port link-type trunk"
echo " port trunk permit vlan 1"
echo " dhcp snooping trust"
echo " quit"
echo

if [[ "$FIRST_SWITCH" == "y" ]]; then
    echo "This is the FIRST switch in your setup."
else
    echo "This is an additional switch (will be adjusted later for VLANs)."
fi

read -p "Have you configured the uplink port? (y/n): " uplink_done

# Phase 7: VLAN 1 + IP
echo
echo "=== Phase 7: Configure VLAN 1 and Management IP ==="
echo "Run these commands:"
echo
echo "vlan 1"
echo " name UDM"
echo " description UPLINK-TO-UDM"
echo " dhcp snooping binding record"
echo " quit"
echo
echo "interface Vlan-interface 1"
echo " description UPLINK-TO-UDM"
echo " ip address $MGMT_IP 255.255.255.0"
echo " quit"
echo "save force"
echo

# Phase 8: Enable SSH
echo
echo "=== Phase 8: Enable SSH Access ==="
echo "Run these commands to allow SSH login:"
echo
echo "line vty 0 4"
echo " authentication-mode scheme"
echo " quit"
echo
echo "Then make sure your admin user has service-type ssh."
echo

echo "=========================================="
echo "Initial setup phase complete."
echo "You should now be able to SSH into the switch using:"
echo "ssh admin@$MGMT_IP"
echo "=========================================="
