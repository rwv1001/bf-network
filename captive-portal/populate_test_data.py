#!/usr/bin/env python3
"""
Populate database with realistic test data for pagination testing
"""
import os
import sys
import random
from datetime import datetime, timedelta
from faker import Faker

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app import app, db
from models import User, Device

fake = Faker()

# Device types
DEVICE_TYPES = ['laptop', 'phone', 'tablet', 'desktop', 'iot']

# User statuses with their VLANs
STATUSES = {
    'friars': 10,
    'staff': 20,
    'students': 30,
    'guests': 40,
    'contractors': 50,
    'volunteers': 60
}

# SSIDs
SSIDS = ['BF-Staff', 'BF-Guest', 'BF-Student', 'BF-Secure']

def generate_mac_address():
    """Generate a random MAC address"""
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

def create_users(count=35):
    """Create realistic test users"""
    print(f"Creating {count} test users...")
    users_created = 0
    
    for i in range(count):
        first_name = fake.first_name()
        last_name = fake.last_name()
        email = f"{first_name.lower()}.{last_name.lower()}.{random.randint(1, 999)}@example.com"
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            continue
        
        status = random.choice(list(STATUSES.keys()))
        
        # Random begin date in the past
        begin_date = fake.date_between(start_date='-2y', end_date='today')
        
        # 70% have expiry dates, 30% are permanent
        if random.random() < 0.7:
            expiry_date = fake.date_between(start_date='today', end_date='+1y')
        else:
            expiry_date = None
        
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone_number=fake.phone_number()[:20],
            status=status,
            begin_date=begin_date,
            expiry_date=expiry_date,
            notes=fake.sentence() if random.random() < 0.3 else '',
            created_by='test_script'
        )
        
        db.session.add(user)
        users_created += 1
        
        if users_created % 10 == 0:
            db.session.flush()
            print(f"  Created {users_created} users...")
    
    db.session.commit()
    print(f"✓ Created {users_created} users")
    return users_created

def create_devices(count=45):
    """Create realistic test devices"""
    print(f"Creating {count} test devices...")
    
    # Get all users
    all_users = User.query.all()
    if not all_users:
        print("Error: No users found. Create users first.")
        return 0
    
    devices_created = 0
    
    for i in range(count):
        mac_address = generate_mac_address()
        
        # Check if MAC already exists
        if Device.query.filter_by(mac_address=mac_address).first():
            continue
        
        user = random.choice(all_users)
        device_type = random.choice(DEVICE_TYPES)
        
        # 90% active, 10% blocked
        registration_status = 'active' if random.random() < 0.9 else 'blocked'
        
        # 80% wifi, 20% wired
        connection_type = 'wifi' if random.random() < 0.8 else 'wired'
        
        ssid = random.choice(SSIDS) if connection_type == 'wifi' else None
        
        # Random first_seen in the past
        first_seen = fake.date_time_between(start_date='-1y', end_date='now')
        
        # Last seen is after first seen, 80% recent (last 7 days)
        if random.random() < 0.8:
            last_seen = fake.date_time_between(start_date='-7d', end_date='now')
        else:
            last_seen = fake.date_time_between(start_date=first_seen, end_date='now')
        
        # Get VLAN from user status
        current_vlan = STATUSES.get(user.status, 40)
        
        device = Device(
            mac_address=mac_address,
            user_id=user.id,
            device_name=device_type,
            registration_status=registration_status,
            connection_type=connection_type,
            ssid=ssid,
            first_seen=first_seen,
            last_seen=last_seen,
            current_vlan=current_vlan
        )
        
        db.session.add(device)
        devices_created += 1
        
        if devices_created % 10 == 0:
            db.session.flush()
            print(f"  Created {devices_created} devices...")
    
    db.session.commit()
    print(f"✓ Created {devices_created} devices")
    return devices_created

def main():
    with app.app_context():
        print("=" * 60)
        print("Populating database with test data")
        print("=" * 60)
        
        # Check current counts
        existing_users = User.query.count()
        existing_devices = Device.query.count()
        
        print(f"\nCurrent database state:")
        print(f"  Users: {existing_users}")
        print(f"  Devices: {existing_devices}")
        print()
        
        # Create test data
        users_created = create_users(35)
        devices_created = create_devices(45)
        
        # Final counts
        total_users = User.query.count()
        total_devices = Device.query.count()
        
        print()
        print("=" * 60)
        print("Summary:")
        print(f"  Total users: {total_users} (+{users_created})")
        print(f"  Total devices: {total_devices} (+{devices_created})")
        print("=" * 60)
        print("\n✓ Test data population complete!")
        print("  You can now test pagination in the admin dashboard.")

if __name__ == '__main__':
    main()
