#!/bin/bash
detect_switch_serial_port() {
    echo "Scanning for HP 5130 switch on serial ports..."

    for port in /dev/ttyUSB{0..7}; do
        [ -e "$port" ] || continue

        echo "Testing $port ..."

        # Configure the serial port
        stty -F "$port" 9600 cs8 -cstopb -parenb raw -echo 2>/dev/null || continue

        # Flush any old data
        timeout 0.5 cat < "$port" > /dev/null 2>&1

        # Send TWO carriage returns (this switch needs it)
        echo -e "\r\r" > "$port"

        # Read response for up to 6 seconds
        response=$(timeout 6 cat < "$port" 2>/dev/null || true)

        # Check for typical HP switch responses
        if echo "$response" | grep -qiE 'Line aux|Automatic configuration|Login:|Password:|<'; then
            echo "✅ HP switch detected on: $port"
            DETECTED_PORT="$port"
            return 0
        fi
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
