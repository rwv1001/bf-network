#!/usr/bin/env python3
"""
Update HP 5130 ACLs for Four-Pool Configuration with BLOCKED Pool

This script updates existing ACLs to add rules for the BLOCKED pool (.224-.254).
The blocked pool has the same walled garden access as unregistered devices,
but the captive portal will display a "blocked" message instead of registration form.

Pool structure:
- .5-.127    : REGISTERED (full access)
- .128-.191  : NEWLY_UNREGISTERED (walled garden)
- .192-.223  : OLD_UNREGISTERED (walled garden)
- .224-.254  : BLOCKED (walled garden + blocked message)
"""

import os
from netmiko import ConnectHandler
import argparse
from getpass import getpass

_sh_raw = os.getenv('SWITCH_HOSTS', '')
portal_ip_byte = os.getenv('PORTAL_IP_BYTE', '4').strip()
_sh_hosts = [h.strip() for h in _sh_raw.split() if h.strip()]

# Switch connection details
SWITCH_CONFIG = {
    'device_type': 'hp_comware',
    'host': _sh_hosts[0] if _sh_hosts else '',
    'username': 'admin',
    'password': '',
    'session_log': 'hp5130_acl_update.log',
    'timeout': 30,
}

VLANS = [10, 20, 30, 40, 50, 60, 70, 80, 90]


def update_acl_for_blocked_pool(connection, vlan_id):
    """Update ACL to add rules for blocked pool (.224-.254)"""
    
    acl_num = 3000 + (vlan_id * 10)
    network = f"{os.getenv('NETWORK_WORD', '192.168')}.{vlan_id}"
    
    commands = []
    
    # Enter ACL configuration
    commands.append(f'acl advanced {acl_num}')
    
    # Add comment about blocked pool
    commands.append(f' description "VLAN{vlan_id} Walled Garden with BLOCKED pool (.224-.254)"')
    
    # Add rules for blocked pool (.224-.254) - same as walled garden
    # These are added AFTER the existing rule 60 but BEFORE rule 100
    commands.extend([
        f' rule 65 permit udp source {network}.224 0.0.0.31 destination 255.255.255.255 0 destination-port eq bootps',
        f' rule 66 permit tcp source {network}.224 0.0.0.31 destination {network}.{portal_ip_byte} 0 destination-port eq www',
        f' rule 67 permit tcp source {network}.224 0.0.0.31 destination {network}.{portal_ip_byte} 0 destination-port eq 443',
        f' rule 68 permit tcp source {network}.224 0.0.0.31 destination {network}.{portal_ip_byte} 0 destination-port eq 8080',
        f' rule 69 permit udp source {network}.224 0.0.0.31 destination-port eq dns',
        f' rule 70 permit tcp source {network}.224 0.0.0.31 destination-port eq dns',
        f' rule 71 permit udp source {network}.224 0.0.0.31 destination-port eq ntp',
        f' rule 72 permit icmp source {network}.224 0.0.0.31 destination {network}.{portal_ip_byte} 0',
    ])
    
    # Deny all other traffic from blocked pool
    commands.append(f' rule 73 deny ip source {network}.224 0.0.0.31')
    
    commands.append(' quit')
    
    return commands


def main():
    parser = argparse.ArgumentParser(description='Update HP 5130 ACLs for BLOCKED pool')
    parser.add_argument('--dry-run', action='store_true', help='Show commands without applying')
    parser.add_argument('--password', type=str, help='Switch password')
    args = parser.parse_args()
    
    if not args.password:
        SWITCH_CONFIG['password'] = getpass(f"Enter password for {SWITCH_CONFIG['username']}@{SWITCH_CONFIG['host']}: ")
    else:
        SWITCH_CONFIG['password'] = args.password
    
    print(f"\n{'='*70}")
    print("HP 5130 ACL Update for BLOCKED Pool (.224-.254)")
    print(f"{'='*70}")
    print(f"Switch: {SWITCH_CONFIG['host']}")
    print(f"VLANs: {', '.join(map(str, VLANS))}")
    print(f"Mode: {'DRY RUN' if args.dry_run else 'LIVE'}")
    print(f"{'='*70}\n")
    
    if args.dry_run:
        print("Commands that would be executed:\n")
        print("system-view")
        for vlan_id in VLANS:
            commands = update_acl_for_blocked_pool(None, vlan_id)
            print(f"\n# VLAN {vlan_id}")
            for cmd in commands:
                print(cmd)
        print("return")
        print("\nDRY RUN COMPLETE - No changes made")
        return
    
    # Connect to switch
    print("Connecting to switch...")
    try:
        connection = ConnectHandler(**SWITCH_CONFIG)
        print(f"✓ Connected to {SWITCH_CONFIG['host']}\n")
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        return 1
    
    try:
        connection.send_command('system-view', expect_string=r']')
        
        for vlan_id in VLANS:
            print(f"{'─'*70}")
            print(f"Updating ACL for VLAN {vlan_id}...")
            print(f"{'─'*70}")
            
            commands = update_acl_for_blocked_pool(connection, vlan_id)
            output = connection.send_config_set(commands)
            
            # Verify
            acl_num = 3000 + (vlan_id * 10)
            verify = connection.send_command(f'display acl {acl_num}')
            
            if 'rule 65' in verify and 'rule 73' in verify:
                print(f"✓ VLAN {vlan_id} ACL updated successfully")
            else:
                print(f"⚠ VLAN {vlan_id} ACL update verification failed")
            print()
        
        connection.send_command('return', expect_string=r'>')
        
        # Save configuration
        save = input("\nSave configuration to switch? (yes/no): ")
        if save.lower() in ['yes', 'y']:
            print("Saving configuration...")
            save_output = connection.send_command_timing('save')
            if '[Y/N]' in save_output or 'Y/N' in save_output:
                save_output = connection.send_command_timing('Y')
            print("✓ Configuration saved")
        else:
            print("⚠ Configuration NOT saved - changes will be lost on reboot!")
        
        connection.disconnect()
        print(f"\n{'='*70}")
        print("ACL update complete!")
        print(f"{'='*70}\n")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        connection.disconnect()
        return 1


if __name__ == '__main__':
    main()
