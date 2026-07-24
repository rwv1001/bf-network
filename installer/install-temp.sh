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

get_interface() {
    local port=$1
    local max_1g_port=$2

    if [ "$port" -le "$max_1g_port" ]; then
        echo "GigabitEthernet1/0/$port"
    else
        echo "Ten-GigabitEthernet1/0/$port"
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
IPS=()


echo
echo "=== Phase 2: Choose Management IP for the Switch ==="
echo
echo
read -p "How many HP5130 switches would you like to set up? " NUM_SWITCHES



read -p "Would you like to scan the network for used IPs? (y/n): " scan_network

    # Fix: Use HOST_IP instead of undefined CURRENT_SUBNET
CURRENT_SUBNET="$HOST_IP"

if [[ "$scan_network" == "y" ]]; then  

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
fi




declare -a NUMBER_OF_PORTS
declare -a MAX_1GBS_PORT

for ((i=1; i<=NUM_SWITCHES; i++)); do
    idx=$((i - 1))

    read -p "Enter the management IP for switch #$i: " ip
    IPS+=("$ip")

    read -p "Enter the number of ports for switch #$i: " num_ports
    NUMBER_OF_PORTS[$idx]="$num_ports"

    read -p "What is the maximum 1Gbps port for switch #$i: " max_1gbs_port
    MAX_1GBS_PORT[$idx]="$max_1gbs_port"
done

 for ((i=1; i<=NUM_SWITCHES; i++)); do
    echo "Switch #$i: ${IPS[$i-1]} (Ports: ${NUMBER_OF_PORTS[$((i - 1))]}, Max 1Gbps Port: ${MAX_1GBS_PORT[$((i - 1))]})"
 done


# ==========================================
# VLAN Configuration
# ==========================================
echo
echo "=== VLAN Setup ==="

read -p "Enter VLAN IDs (space separated, strictly increasing, e.g. 10 20 30): " -a VLAN_LIST

original_input="${VLAN_LIST[*]}"

# Remove duplicates and sort numerically
VLAN_LIST=($(printf "%s\n" "${VLAN_LIST[@]}" | sort -n -u))

sorted_input="${VLAN_LIST[*]}"

if [ "$original_input" != "$sorted_input" ]; then
    echo "Note: VLANs were automatically sorted into increasing order: $sorted_input"
fi

# Validate that VLANs are strictly increasing and ≤ 90
for ((i=0; i<${#VLAN_LIST[@]}-1; i++)); do
    current="${VLAN_LIST[$i]}"
    next="${VLAN_LIST[$((i + 1))]}"

    if [ "$current" -ge "$next" ]; then
        echo "Error: VLAN IDs must be strictly increasing."
        exit 1
    fi

    if [ "$current" -gt 90 ] || [ "$next" -gt 90 ]; then
        echo "Error: All VLANs must be 90 or less."
        exit 1
    fi

    diff=$((next - current))
    if [ "$diff" -lt 8 ]; then
        echo "Error: VLANs must be at least 8 apart. $current and $next are too close."
        exit 1
    fi
done

# Get names for each VLAN
declare -A VLAN_NAMES
for  ((v=1; v<=${#VLAN_LIST[@]}; v++)); do
    read -p "Enter name for VLAN ${VLAN_LIST[$((v - 1))]}: " name
    VLAN_NAMES[$((v - 1))]="$name"
done

# Local network base (e.g. 10.0, 172.20, 192.168)
# ==========================================
# Get and validate Local Network Base
# ==========================================
while true; do
    read -p "Enter local network base (e.g. 10.5, 172.20 or 192.168): " LOCAL_BASE

    # Check format (must be X.Y)
    if ! [[ "$LOCAL_BASE" =~ ^[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Please enter in the format X.Y (e.g. 10.5 or 192.168)"
        continue
    fi

    # Split into octets
    IFS='.' read -r first_octet second_octet <<< "$LOCAL_BASE"

    # Validate against private IP ranges
    valid=false

    if [ "$first_octet" -eq 10 ] && [ "$second_octet" -ge 0 ] && [ "$second_octet" -le 255 ]; then
        valid=true
    elif [ "$first_octet" -eq 172 ] && [ "$second_octet" -ge 16 ] && [ "$second_octet" -le 31 ]; then
        valid=true
    elif [ "$first_octet" -eq 192 ] && [ "$second_octet" -eq 168 ]; then
        valid=true
    fi

    if [ "$valid" = true ]; then
        break
    else
        echo "Error: $LOCAL_BASE is not in a valid private range."
        echo "Allowed ranges:"
        echo "  - 10.0   to 10.255   (10.0.0.0/8)"
        echo "  - 172.16 to 172.31   (172.16.0.0/12)"
        echo "  - 192.168            (192.168.0.0/16)"
    fi
done

echo "Using local network base: $LOCAL_BASE"

# Special VLANs
read -p "Enter Management VLAN ID (e.g. 99): " MANAGEMENT_VLAN
read -p "Enter Wired Guest VLAN ID (e.g. 250): " WIRED_VLAN

# ==========================================
# Number of ISPs
# ==========================================
while true; do
    read -p "How many ISPs are there? (1-4): " NUM_ISPS
    if [[ "$NUM_ISPS" =~ ^[1-7]$ ]]; then
        break
    else
        echo "Please enter a number between 1 and 4."
    fi
done
# ISP VLANs (1 to NUM_ISPS)
declare -A ISP_NAMES
declare -A ISP_NETWORK_PORTION
ISP_VLAN_CONFIG=""
for ((v=1; v<=NUM_ISPS; v++)); do
    read -p "Enter name for ISP VLAN $v (router/ISP name): " isp_name
    ISP_NAMES[$((v - 1))]="$isp_name"
    if [ "$v" -eq 1 ]; then
        CURRENT_THREE_OCTETS=$(echo "$CURRENT_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3)
        echo "For ISP VLAN $v ($isp_name), using network portion from current subnet: $CURRENT_THREE_OCTETS"
        ISP_NETWORK_PORTION[$((v - 1))]="$CURRENT_THREE_OCTETS"
    else
        read -p "Enter ISP VLAN network portion for VLAN $v (e.g. 10.5.2 or 192.168.2): " isp_network_portion
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

# Build VLAN configuration block
VLAN_CONFIG=""
for ((v=1; v<=${#VLAN_LIST[@]}; v++)); do
    vlan="${VLAN_LIST[$((v - 1))]}"
    name="${VLAN_NAMES[$((v - 1))]}"
    VLAN_CONFIG+="
vlan $vlan
name $name
dhcp snooping binding record
arp detection enable
#
"
done











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

# ==========================================
# Phase 3: Collect required information
# ==========================================



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







# ==========================================
# Main Loop - Configure each switch
# ==========================================
m=0   # Number of ISP uplink ports already assigned

for i in "${!IPS[@]}"; do
    MGMT_IP="${IPS[$i]}"
    SWITCH_NUM=$((i + 1))
    IS_LAST_SWITCH=$(( i == ${#IPS[@]} - 1 ))



    
    

    echo
    echo "=========================================="
    echo "   Configuring Switch #$SWITCH_NUM ($MGMT_IP)"
    echo "=========================================="

    while true; do
        read -p "Is a Kea Pi server being connected to this switch? Enter port number (1-${NUMBER_OF_PORTS[$i]}) or press Enter for none: " KEA_PORT

        # Allow empty input (no Kea Pi server)
        if [[ -z "$KEA_PORT" ]]; then
            KEA_PORT=""
            break
        fi

        # Must be a positive integer
        if ! [[ "$KEA_PORT" =~ ^[0-9]+$ ]]; then
            echo "Please enter a valid number or press Enter for none."
            continue
        fi

        # Must be within the valid port range for this switch
        if [ "$KEA_PORT" -lt 1 ] || [ "$KEA_PORT" -gt "${NUMBER_OF_PORTS[$i]}" ]; then
            echo "Port must be between 1 and ${NUMBER_OF_PORTS[$i]}."
            continue
        fi

        # (Optional) You can later add a check here to ensure the port isn't already used
        # as an uplink or inter-switch link on this switch.

        break
    done

    

    # Ask for credentials for this switch
    read -sp "Enter the CURRENT admin password for this switch: " CURRENT_PASSWORD
    echo

    # Ask for new admin password (optional)
    read -p "Enter NEW admin password for this switch (or press Enter to keep current): " NEW_ADMIN_PASSWORD
    
        # --- ISP Uplink Ports ---
    
    UPLINK_PORTS=()
    while [ $((NUM_ISPS - m)) -gt 0 ]; do
        read -p "Enter ISP uplink port (1-${NUMBER_OF_PORTS[$i]}) or press Enter to finish uplinks for this switch: " port

        if [[ -z "$port" ]]; then
            if [ "$IS_LAST_SWITCH" -eq 1 ]; then
                echo "You must assign all remaining ISP uplinks on the last switch."
                continue
            else
                break
            fi
        fi

        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt ${NUMBER_OF_PORTS[$i]} ]; then
            echo "Invalid port. Please enter a number between 1 and ${NUMBER_OF_PORTS[$i]}."
            continue
        fi

        if [[ " ${UPLINK_PORTS[*]} " =~ " $port " ]]; then
            echo "Port $port is already assigned as an uplink on this switch."
            continue
        fi

        UPLINK_PORTS+=("$port")
        
        ((++m))
    done

    # --- Inter-switch Links ---
    INTERSWITCH_PORTS=()
    while true; do
        read -p "Enter inter-switch link port (1-52) or press Enter to finish: " port

        if [[ -z "$port" ]]; then
            break
        fi

        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 52 ]; then
            echo "Invalid port. Please enter a number between 1 and 52."
            continue
        fi

        if [[ " ${INTERSWITCH_PORTS[*]} " =~ " $port " ]]; then
            echo "Error: Port $port is already used as an inter-switch link on this switch."
            continue
        fi

        INTERSWITCH_PORTS+=("$port")
    done

    # Build VLAN Interface configuration
    # Get last octet of management IP (e.g. 25 from 192.168.1.25)
    LAST_OCTET=$(echo "$MGMT_IP" | cut -d'.' -f4)

    # Build VLAN Interface configuration
    VLAN_IFACE_CONFIG=""
    for ((v=1; v<=NUM_ISPS; v++)); do
        VLAN_IFACE_CONFIG+="
    interface Vlan-interface$v
    description UPLINK-TO-${ISP_NAMES[$((v - 1))]}
    ip address ${ISP_NETWORK_PORTION[$((v - 1))]}.${LAST_OCTET} 255.255.255.0
    #
    "
    done


    # Build VLAN Interface configuration
    
    for vlan in "${VLAN_LIST[@]}"; do
        VLAN_IFACE_CONFIG+="
    interface Vlan-interface$vlan
    description GW_VLAN$vlan
    ip address ${LOCAL_BASE}.${vlan}.${LAST_OCTET} 255.255.255.0
    #
    "
    done

    



    # ISP Uplink ports
    UPLINK_CONFIG=""
    for ((v=1; v<=${#UPLINK_PORTS[@]}; v++)); do
        port=${UPLINK_PORTS[$((v - 1))]}
        iface=$(get_interface "$port" "${MAX_1GBS_PORT[$i]}")
        UPLINK_CONFIG+="  
    interface $iface      
    description UPLINK-TO-${ISP_NAMES[$((v - 1))]}
    port link-type trunk
    port trunk permit vlan $v    
    dhcp snooping trust
    #
    "
    done

    # Inter-switch links
    INTERSWITCH_CONFIG=""
    for port in "${INTERSWITCH_PORTS[@]}"; do  
        iface=$(get_interface "$port" "${MAX_1GBS_PORT[$i]}")         
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

    # Kea Pi port config (if provided)
    KEA_CONFIG=""

    if [[ -n "$KEA_PORT" ]]; then   
        iface=$(get_interface "$KEA_PORT" "${MAX_1GBS_PORT[$i]}")
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



    # Combine all dynamic config
    DYNAMIC_CONFIG="$ISP_VLAN_CONFIG$VLAN_IFACE_CONFIG$UPLINK_CONFIG$INTERSWITCH_CONFIG$KEA_CONFIG"

    if [ $i -eq 0 ]; then
        echo "Please plug the USB serial cable into the Pi and the RJ45 end into the console port of the FIRST switch."
    else
        echo "Please move the RJ45 end of the serial cable to the console port of the NEXT switch ($MGMT_IP)."
    fi
    read -p "Press Enter when ready..."

    # Detect serial port
    echo "=== Phase 4: Detect Serial Port and Configure Switch #$SWITCH_NUM ($MGMT_IP)==="

    if detect_switch_serial_port; then
        echo
        echo "Switch successfully detected on port: $DETECTED_PORT"
    else    
        echo "Failed to detect switch on serial port. Skipping..."
        continue
    fi

    echo
    echo "Configuring switch $MGMT_IP via serial..."

    NP_ARG=""
    if [[ -n "$NEW_ADMIN_PASSWORD" ]]; then
        NP_ARG="-np $NEW_ADMIN_PASSWORD"
    fi

    ./test-switch-temp.exp \
        -port "$DETECTED_PORT" \
        -cp "$CURRENT_PASSWORD" \
        $NP_ARG \
        -user "$NEW_USERNAME" \
        -pubkey "$PUBLIC_KEY" \
        -ip "$MGMT_IP" \
        -up "$UPLINK_PORT" \
        -vlan-config "$VLAN_CONFIG" \
        -dynamic-config "$DYNAMIC_CONFIG" \
        -debug

    echo "Switch $MGMT_IP has been configured."
    
done

echo
echo "All switches have been processed."