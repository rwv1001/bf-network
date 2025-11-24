# Dynamic Subnet Hook for Kea DHCP

This hook library replicates the functionality of the old `user_chk` hook from Kea 1.9.9.

## Functionality

The hook intercepts the `subnet4_select` hook point and dynamically selects the subnet based on whether the client MAC address has a host reservation in the PostgreSQL hosts database:

- **Has reservation** → First subnet (registered pool: .5-.127, 24h lease, public DNS)
- **No reservation** → Last subnet (unregistered pool: .128-.254, 60s lease, captive DNS)

This runs on **every DHCP packet** (DISCOVER, REQUEST, RENEW, REBIND), ensuring immediate enforcement of registration status changes.

## Building

### Prerequisites

```bash
# Install build tools and Kea development headers
apt-get update
apt-get install -y build-essential cmake g++ libkea-dev
```

### Compile

```bash
cd /home/admin/bf-network/kea-hooks/dynamic_subnet
mkdir build
cd build
cmake ..
make
sudo make install
```

This installs `dhcp_dynamic_subnet.so` to `/usr/local/lib/kea/hooks/`

## Kea Configuration

Add to `/home/admin/bf-network/kea/config/dhcp4.json`:

```json
{
  "Dhcp4": {
    "hooks-libraries": [
      {
        "library": "/usr/local/lib/kea/hooks/libdhcp_pgsql.so"
      },
      {
        "library": "/usr/local/lib/kea/hooks/libdhcp_host_cmds.so"
      },
      {
        "library": "/usr/local/lib/kea/hooks/libdhcp_lease_cmds.so"
      },
      {
        "library": "/usr/local/lib/kea/hooks/dhcp_dynamic_subnet.so"
      }
    ],
    "subnet4": [
      {
        "subnet": "192.168.10.0/24",
        "id": 10,
        "pools": [
          {
            "pool": "192.168.10.5 - 192.168.10.127",
            "comment": "Registered pool - MUST BE FIRST"
          },
          {
            "pool": "192.168.10.128 - 192.168.10.254",
            "comment": "Unregistered pool - MUST BE LAST"
          }
        ]
      }
    ]
  }
}
```

**Important:** Pool order matters! First pool = registered, last pool = unregistered.

## Testing

1. Add a host reservation:
   ```bash
   echo '{"command":"reservation-add","arguments":{"reservation":{"hw-address":"aa:bb:cc:dd:ee:ff","subnet-id":10}}}' | nc -U /kea/sockets/kea4-ctrl-socket
   ```

2. Device with MAC `aa:bb:cc:dd:ee:ff` will immediately get an IP from the registered pool (.5-.127) on its next DHCP request (even RENEW).

3. Remove the reservation:
   ```bash
   echo '{"command":"reservation-del","arguments":{"subnet-id":10,"identifier-type":"hw-address","identifier":"aa:bb:cc:dd:ee:ff"}}' | nc -U /kea/sockets/kea4-ctrl-socket
   ```

4. Device will immediately fall back to unregistered pool (.128-.254) on its next DHCP request.

## Docker Integration

To build and install in the Kea container, you'll need to:

1. Add build tools to the container
2. Mount the hook source code
3. Build inside the container
4. Update Kea configuration

See `DOCKER_BUILD.md` for detailed instructions.
