#!/usr/bin/env python3
"""
Test HP5130 Switch Connection and ACL Management

Quick test to verify:
1. SSH connectivity to switch
2. ACL viewing works
3. ACL rule addition works
4. ACL rule removal works
"""

import os
import sys
from getpass import getpass
from pathlib import Path

# Add captive-portal/app to path
repo_root = Path(__file__).resolve().parent
sys.path.insert(0, str(repo_root / 'captive-portal' / 'app'))

try:
    from switch_acl_manager import SwitchACLManager
except ImportError:
    print("Error: Cannot import switch_acl_manager")
    print("Run this script from the repository root")
    sys.exit(1)


def test_connection(manager, vlan_id=10):
    """Test basic connectivity and ACL viewing"""
    print(f"\n{'='*70}")
    print("TEST 1: Switch Connection and ACL Viewing")
    print(f"{'='*70}")
    
    try:
        print(f"Attempting to connect to {manager.host}...")
        from netmiko import ConnectHandler
        
        connection = ConnectHandler(**manager.device_config)
        print(f"✓ Connected successfully!")
        
        acl_num = manager._get_acl_number(vlan_id)
        print(f"\nFetching ACL {acl_num} (VLAN {vlan_id})...")
        output = connection.send_command(f'display acl {acl_num}')
        
        # Show first 500 chars
        print(f"\n--- ACL Output (first 500 chars) ---")
        print(output[:500])
        print(f"--- End of ACL Output ---\n")
        
        connection.disconnect()
        print(f"✓ TEST 1 PASSED - Connection and ACL viewing works")
        return True
        
    except Exception as e:
        print(f"✗ TEST 1 FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_block_unblock(manager, test_ip, vlan_id=10):
    """Test blocking and unblocking an IP"""
    print(f"\n{'='*70}")
    print("TEST 2: Block and Unblock IP Address")
    print(f"{'='*70}")
    
    print(f"\nAttempting to block {test_ip} on VLAN {vlan_id}...")
    success, message = manager.block_ip(test_ip, vlan_id)
    
    if not success:
        print(f"✗ TEST 2 FAILED - Block failed: {message}")
        return False
    
    print(f"✓ Block succeeded: {message}")
    
    # Verify block exists
    print(f"\nVerifying block exists...")
    blocked_ips = manager.list_blocked_ips(vlan_id)
    if any(ip == test_ip for _, ip in blocked_ips):
        print(f"✓ Verified: {test_ip} is in blocked list")
    else:
        print(f"✗ Verification failed: {test_ip} not found in blocked list")
        print(f"   Blocked IPs: {blocked_ips}")
        return False
    
    # Now unblock
    print(f"\nAttempting to unblock {test_ip}...")
    success, message = manager.unblock_ip(test_ip, vlan_id)
    
    if not success:
        print(f"✗ TEST 2 FAILED - Unblock failed: {message}")
        return False
    
    print(f"✓ Unblock succeeded: {message}")
    
    # Verify block removed
    print(f"\nVerifying block removed...")
    blocked_ips = manager.list_blocked_ips(vlan_id)
    if not any(ip == test_ip for _, ip in blocked_ips):
        print(f"✓ Verified: {test_ip} removed from blocked list")
    else:
        print(f"✗ Verification failed: {test_ip} still in blocked list")
        print(f"   Blocked IPs: {blocked_ips}")
        return False
    
    print(f"✓ TEST 2 PASSED - Block and unblock works")
    return True


def main():
    print("HP5130 Switch ACL Management - Connection Test")
    print("="*70)
    
    # Get credentials
    host = os.environ['SWITCH_HOST']
    user = os.getenv('SWITCH_USER', 'admin')
    password = os.getenv('SWITCH_PASS', '')
    
    if not password:
        password = getpass(f"Enter password for {user}@{host}: ")
    
    print(f"\nSwitch: {host}")
    print(f"Username: {user}")
    
    # Create manager
    manager = SwitchACLManager(host=host, username=user, password=password)
    
    # Test 1: Connection and ACL viewing
    if not test_connection(manager):
        print("\n❌ CONNECTION TEST FAILED - Cannot proceed with further tests")
        sys.exit(1)
    
    # Ask for test IP
    print(f"\n{'='*70}")
    test_ip = input("Enter a test IP address to block/unblock (e.g., 192.168.10.254): ").strip()
    
    if not test_ip:
        print("No test IP provided, skipping block/unblock test")
        print("\n✓ ALL TESTS COMPLETED (connection test only)")
        sys.exit(0)
    
    # Extract VLAN from IP
    try:
        octets = test_ip.split('.')
        vlan_id = int(octets[2])
        print(f"Detected VLAN: {vlan_id}")
    except:
        print("Invalid IP format, using VLAN 10")
        vlan_id = 10
    
    # Test 2: Block and unblock
    if not test_block_unblock(manager, test_ip, vlan_id):
        print("\n❌ BLOCK/UNBLOCK TEST FAILED")
        sys.exit(1)
    
    # All tests passed
    print(f"\n{'='*70}")
    print("✅ ALL TESTS PASSED - Switch ACL management is working correctly")
    print(f"{'='*70}\n")
    
    print("Next steps:")
    print("1. Set SWITCH_PASS environment variable in .env file")
    print("2. Rebuild captive portal: docker-compose build")
    print("3. Restart captive portal: docker-compose up -d")
    print("4. Test blocking from admin dashboard\n")


if __name__ == '__main__':
    main()
