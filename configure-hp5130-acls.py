#!/usr/bin/env python3
"""
HP 5130 Walled Garden ACL Configuration Script

This script automatically configures ACLs on the HP 5130 switch to create
a walled garden for the captive portal. Unregistered devices can only access
the portal, while registered devices have full internet access.

Requirements:
    pip install netmiko

Usage:
    python3 configure-hp5130-acls.py
"""

from netmiko import ConnectHandler
import sys
import argparse
from getpass import getpass

# Switch connection details
SWITCH_CONFIG = {
    'device_type': 'hp_comware',
    'host': '192.168.99.1',  # Your HP 5130 management IP
    'username': 'admin',      # Change as needed
    'password': '',           # Will prompt if not provided
    'session_log': 'hp5130_session.log',
    'timeout': 30,
}

# VLANs to configure
VLANS = [
    {'id': 10, 'network': '192.168.10', 'name': 'VLAN10'},
    {'id': 20, 'network': '192.168.20', 'name': 'VLAN20'},
    {'id': 30, 'network': '192.168.30', 'name': 'VLAN30'},
    {'id': 40, 'network': '192.168.40', 'name': 'VLAN40'},
    {'id': 50, 'network': '192.168.50', 'name': 'VLAN50'},
    {'id': 60, 'network': '192.168.60', 'name': 'VLAN60'},
    {'id': 70, 'network': '192.168.70', 'name': 'VLAN70'},
    {'id': 90, 'network': '192.168.90', 'name': 'VLAN90'},
]

# Portal IP suffix (e.g., .4 means 192.168.X.4)
PORTAL_IP_SUFFIX = '.4'

# IP ranges
UNREGISTERED_START = '.128'
UNREGISTERED_WILDCARD = '0.0.0.127'  # Matches .128-.255
REGISTERED_START = '.5'
REGISTERED_WILDCARD = '0.0.0.122'    # Matches .5-.127


def generate_acl_commands(vlan):
    """Generate ACL configuration commands for a VLAN."""
    vlan_id = vlan['id']
    network = vlan['network']
    portal_ip = network + PORTAL_IP_SUFFIX
    unreg_source = network + UNREGISTERED_START
    reg_source = network + REGISTERED_START
    
    # ACL number: 30X0 for the combined ACL
    acl_num = 3000 + (vlan_id * 10)
    
    commands = []
    
    # Combined ACL with registered first (permit all), then unregistered (walled garden)
    commands.extend([
        f'acl advanced {acl_num} match-order auto',
        f' description "VLAN{vlan_id} Walled Garden and Full Access"',
        # Registered devices - full access (check first)
        f' rule 10 permit ip source {reg_source} {REGISTERED_WILDCARD} destination any',
        # Unregistered devices - portal only
        f' rule 20 permit udp source {unreg_source} {UNREGISTERED_WILDCARD} destination {portal_ip} 0 destination-port eq 53',
        f' rule 30 permit tcp source {unreg_source} {UNREGISTERED_WILDCARD} destination {portal_ip} 0 destination-port eq 80',
        f' rule 40 permit tcp source {unreg_source} {UNREGISTERED_WILDCARD} destination {portal_ip} 0 destination-port eq 443',
        f' rule 50 permit udp source {unreg_source} {UNREGISTERED_WILDCARD} destination 255.255.255.255 0 destination-port eq 67',
        f' rule 60 permit udp source {unreg_source} {UNREGISTERED_WILDCARD} destination any destination-port eq 123',
        # Block everything else from unregistered range
        f' rule 100 deny ip source {unreg_source} {UNREGISTERED_WILDCARD} destination any',
        ' quit',
    ])
    
    # Apply ACL to VLAN interface
    commands.extend([
        f'interface Vlan-interface{vlan_id}',
        f' packet-filter {acl_num} outbound',
        ' quit',
    ])
    
    return commands, acl_num


def verify_acl(connection, acl_number):
    """Verify ACL configuration."""
    output = connection.send_command(f'display acl {acl_number}')
    return output


def verify_interface_acl(connection, vlan_id):
    """Verify ACLs applied to interface."""
    output = connection.send_command(f'display packet-filter interface Vlan-interface{vlan_id}')
    return output


def remove_existing_acls(connection, vlan):
    """Remove existing ACLs for a VLAN (cleanup before reconfiguration)."""
    vlan_id = vlan['id']
    acl_num = 3000 + (vlan_id * 10)
    
    commands = []
    
    # Remove ACL from interface first
    commands.extend([
        f'interface Vlan-interface{vlan_id}',
        f' undo packet-filter {acl_num} outbound',
        ' quit',
    ])
    
    # Delete ACL
    commands.append(f'undo acl advanced {acl_num}')
    
    print(f"  Removing existing ACL for VLAN {vlan_id}...")
    try:
        output = connection.send_config_set(commands)
        return True
    except Exception as e:
        print(f"  Warning: Could not remove existing ACL (it may not exist): {e}")
        return False


def configure_switch(dry_run=False, cleanup=False):
    """Configure the HP 5130 switch with walled garden ACLs."""
    
    # Prompt for password if not set
    if not SWITCH_CONFIG['password']:
        SWITCH_CONFIG['password'] = getpass(f"Enter password for {SWITCH_CONFIG['username']}@{SWITCH_CONFIG['host']}: ")
    
    print(f"\n{'='*70}")
    print(f"HP 5130 Walled Garden ACL Configuration")
    print(f"{'='*70}")
    print(f"Switch: {SWITCH_CONFIG['host']}")
    print(f"VLANs to configure: {', '.join([str(v['id']) for v in VLANS])}")
    print(f"Mode: {'DRY RUN (no changes will be made)' if dry_run else 'LIVE (changes will be applied)'}")
    if cleanup:
        print(f"Cleanup: Will remove existing ACLs first")
    print(f"{'='*70}\n")
    
    if dry_run:
        print("DRY RUN MODE - Commands that would be executed:\n")
        for vlan in VLANS:
            commands, acl_num = generate_acl_commands(vlan)
            print(f"\n# VLAN {vlan['id']} Configuration:")
            print("system-view")
            for cmd in commands:
                print(cmd)
            print("return")
            print("save")
        print(f"\n{'='*70}")
        print("DRY RUN COMPLETE - No changes were made")
        print(f"{'='*70}\n")
        return
    
    # Connect to switch
    print("Connecting to switch...")
    try:
        connection = ConnectHandler(**SWITCH_CONFIG)
        print(f"✓ Connected to {SWITCH_CONFIG['host']}")
    except Exception as e:
        print(f"✗ Failed to connect: {e}")
        sys.exit(1)
    
    try:
        # Enter system view (use expect_string to handle any prompt)
        connection.send_command('system-view', expect_string=r']')
        
        # Configure each VLAN
        for vlan in VLANS:
            vlan_id = vlan['id']
            print(f"\n{'─'*70}")
            print(f"Configuring VLAN {vlan_id}...")
            print(f"{'─'*70}")
            
            # Remove existing ACLs if cleanup requested
            if cleanup:
                remove_existing_acls(connection, vlan)
            
            # Generate and apply new ACL configuration
            commands, acl_num = generate_acl_commands(vlan)
            
            print(f"  Creating ACL {acl_num} (combined walled garden)...")
            print(f"  Applying ACL to Vlan-interface{vlan_id}...")
            
            output = connection.send_config_set(commands)
            
            # Verify configuration
            print(f"\n  Verifying configuration...")
            acl_output = verify_acl(connection, acl_num)
            interface_output = verify_interface_acl(connection, vlan_id)
            
            # Check if ACL is actually configured
            if f'Advanced ACL {acl_num}' in acl_output or f'ACL {acl_num}' in acl_output:
                print(f"  ✓ ACL created successfully")
            else:
                print(f"  ✗ Warning: ACL verification failed")
                print(f"    ACL output: {acl_output[:200]}")
            
            if f'packet-filter {acl_num}' in interface_output or f'ACL {acl_num}' in interface_output:
                print(f"  ✓ ACL applied to interface successfully")
            else:
                print(f"  ✗ Warning: Interface ACL verification failed")
                print(f"    Interface output: {interface_output[:200]}")
        
        # Exit system view (use expect_string to handle any prompt)
        connection.send_command('return', expect_string=r'>')
        
        # Save configuration
        print(f"\n{'='*70}")
        save_prompt = input("Save configuration to switch? (yes/no): ")
        if save_prompt.lower() in ['yes', 'y']:
            print("Saving configuration...")
            save_output = connection.send_command_timing('save')
            if '[Y/N]' in save_output or 'Y/N' in save_output:
                save_output = connection.send_command_timing('Y')
            print("✓ Configuration saved")
        else:
            print("⚠ Configuration NOT saved - changes will be lost on reboot!")
        
        # Disconnect
        connection.disconnect()
        print(f"\n{'='*70}")
        print("Configuration complete!")
        print(f"{'='*70}\n")
        print("Verification commands:")
        print("  display acl 3100")
        print("  display packet-filter interface Vlan-interface10")
        print("\nSession log saved to: hp5130_session.log")
        
    except Exception as e:
        print(f"\n✗ Error during configuration: {e}")
        connection.disconnect()
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Configure HP 5130 walled garden ACLs for captive portal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run (show commands without applying)
  python3 configure-hp5130-acls.py --dry-run

  # Apply configuration
  python3 configure-hp5130-acls.py

  # Remove existing ACLs and apply fresh configuration
  python3 configure-hp5130-acls.py --cleanup

  # Use custom switch IP
  python3 configure-hp5130-acls.py --host 192.168.1.1
        """
    )
    
    parser.add_argument('--dry-run', action='store_true',
                        help='Show commands without applying (default: apply changes)')
    parser.add_argument('--cleanup', action='store_true',
                        help='Remove existing ACLs before applying new configuration')
    parser.add_argument('--host', type=str,
                        help=f'Switch IP address (default: {SWITCH_CONFIG["host"]})')
    parser.add_argument('--username', type=str,
                        help=f'SSH username (default: {SWITCH_CONFIG["username"]})')
    parser.add_argument('--password', type=str,
                        help='SSH password (will prompt if not provided)')
    
    args = parser.parse_args()
    
    # Update configuration from arguments
    if args.host:
        SWITCH_CONFIG['host'] = args.host
    if args.username:
        SWITCH_CONFIG['username'] = args.username
    if args.password:
        SWITCH_CONFIG['password'] = args.password
    
    configure_switch(dry_run=args.dry_run, cleanup=args.cleanup)


if __name__ == '__main__':
    main()
