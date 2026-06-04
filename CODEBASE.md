# Blackfriars Network Portal — Codebase Overview

> **Note**: This document describes the **logical architecture**, data model, and business rules of the system.  
> The implementation has been refactored into a modular structure:
> - `app.py` is now a slim application factory
> - Routes live in `blueprints/`
> - Shared logic lives in `core/`
>
> The rules and data model described below remain the authoritative reference.

## Current Code Organisation

| Layer              | Location                    | Responsibility |
|--------------------|-----------------------------|----------------|
| Application Factory| `app.py`                    | `create_app()`, config, blueprint registration, startup |
| Public Routes      | `blueprints/portal.py`      | Captive portal, registration, user home, adoption |
| Admin Routes       | `blueprints/admin/`         | Dashboard, user/device management |
| Business Logic     | `core/`                     | Device utils, network control, VLAN logic, sweepers, central sync |
| Data Model         | `models.py`                 | SQLAlchemy models |

> The table purposes and relationships described below are stable and have not changed during the code refactor.

Network Device Registration and Access Control System
1. Purpose

This system controls whether devices connected to a network receive full internet access, captive-portal-only access, or blocked-pool access. It supports:

device registration by users or administrators;
per-domain and per-user VLAN access policies;
device adoption by users;
administrator approval workflows;
Wi-Fi and wired Ethernet onboarding;
blocking and unblocking of users or devices;
DHCP lease tracking through Kea hooks;
DNS hijacking and HP5130 ACL enforcement;
optional password-based ownership validation;
multi-premises synchronisation through a central server.

The system treats the database as the source of truth. Network enforcement is performed through:

Kea DHCP hooks;
Pi iptables DNS hijack rules;
HP5130 ACL updates;
RADIUS MAC-to-VLAN assignments for wired devices.
2. Core Data Tables
Table	Purpose
Allowable VLANs per email domain	Defines VLANs where users from a given email domain may receive full access without admin approval.
Allowable VLANs per user	Per-user override for access VLANs. Can allow some VLANs automatically and require approval for others.
Adoptable VLANs per email domain	Defines VLANs where users from a given email domain may adopt unregistered devices without admin approval.
Adoptable VLANs per user	Per-user override for adoption permissions.
MAC address status	One row per observed MAC address. Tracks access status, assigned VLAN, device type, validation state, and first-seen time.
IP status	Tracks DHCP leases, VLAN, MAC address, blocked-pool status, and DNS hijack status.
Users	Stores user identity, email, password, phone, registration date, and expiry date.
MAC address users	Ownership history for MAC addresses. Active ownership is represented by end date/time = null.
VLAN config	Defines VLAN metadata, SSID, wired availability, password requirement, subnet size, and ISP router.
ISP routers	Maps router/VLAN/gateway/HP5130 details used for ACL and DHCP snooping configuration.
RADIUS table	MAC-address-to-VLAN mapping used by the RADIUS server for wired Ethernet assignment. Each MAC appears at most once.
3. Data Model Overview
erDiagram
    USERS ||--o{ MAC_ADDRESS_USERS : owns
    MAC_ADDRESS_STATUS ||--o{ MAC_ADDRESS_USERS : ownership_history
    MAC_ADDRESS_STATUS ||--o{ IP_STATUS : has_leases
    VLAN_CONFIG ||--o{ IP_STATUS : lease_vlan
    VLAN_CONFIG ||--o{ ISP_ROUTERS : served_by
    VLAN_CONFIG ||--o{ RADIUS_TABLE : assigned_vlan
    MAC_ADDRESS_STATUS ||--o| RADIUS_TABLE : wired_assignment

    USERS {
        int user_id PK
        string email UK
        string first_name
        string second_name
        string password
        string telephone
        datetime registration_date
        datetime expiry_date
    }

    MAC_ADDRESS_STATUS {
        string mac_address PK
        boolean internet_accessible
        boolean internet_blocked
        int assigned_vlan
        string device_type
        boolean ownership_validated
        datetime first_seen
    }

    IP_STATUS {
        string ip_address
        int vlan_id
        datetime lease_start
        string mac_address FK
        datetime lease_expiry
        boolean from_blocked_pool
        boolean dns_hijacked
    }

    MAC_ADDRESS_USERS {
        string mac_address FK
        int user_id FK
        datetime start_datetime
        datetime end_datetime
    }

    VLAN_CONFIG {
        string name
        int vlan_id PK
        string ssid
        boolean wired_allowed
        boolean password_required
        int subnet_size
        string isp_router
    }

    ISP_ROUTERS {
        string name
        string subnet
        int vlan_id FK
        string hp5130_port
        boolean dhcp_snoop_trust
        string gateway_ip
    }

    RADIUS_TABLE {
        string mac_address PK
        int vlan_id FK
    }
4. Important State Rules
4.1 MAC status

The MAC address status table is the main state table for device connectivity.

Field	Meaning
internet_accessible = true	The device currently has full internet access. This must only be set after DNS hijacks and HP5130 ACL blocks have actually been removed.
internet_accessible = false	The device is known not to have full access, usually because it is on the wrong VLAN, has not passed required validation, or has been refused access.
internet_accessible = null	No final decision has been made, or the device has no active lease. Kea/captive portal should keep the device captive or blocked.
internet_blocked = true	The device is explicitly blocked and should be placed in the blocked pool where possible.
internet_blocked = null/false	The device is not explicitly blocked, but may still lack access because it is unregistered, awaiting approval, on the wrong VLAN, or unvalidated.
Assigned VLAN	The VLAN where the device is permitted to have access. This should only be non-null when there is an active owner in MAC address users.
ownership_validated	Indicates that the user has confirmed ownership or entered the required password for VLANs requiring validation.
4.2 Access invariant

A device should only have full internet access when all of the following are true:

it is actively registered to a user;
it is not explicitly blocked;
its current VLAN equals Assigned VLAN;
if the VLAN requires a password, ownership_validated = true;
the current lease is not from the blocked pool;
DNS hijack rules have been removed;
HP5130 ACL blocks have been removed;
only then is internet_accessible set to true.
5. VLAN Policy Resolution

There are two related permission systems:

Connection access: whether a user may connect a device on a VLAN and receive full access without admin approval.
Adoption access: whether a user may adopt an unregistered device on a VLAN without admin approval.

Both use the same resolution pattern:

flowchart TD
    A[User requests access or adoption on selected VLAN] --> B{User-specific rule exists?}
    B -->|VLAN in user's Allowable VLANs| C[Allow without admin approval]
    B -->|VLAN in user's Needing Approval VLANs| D[Require admin approval]
    B -->|No relevant user override| E{Email domain rule exists?}
    E -->|VLAN allowed for domain| C
    E -->|No domain rule or VLAN not listed| D

User-specific policy overrides domain policy. A user override can therefore allow a VLAN that the domain does not allow, or require approval for a VLAN that the domain would otherwise allow.

6. DHCP / Kea Behaviour

When a device connects, Kea receives DHCP traffic and updates the database. The behaviour depends on whether the MAC is known, whether the device is blocked, and whether the current lease is in the correct pool.

flowchart TD
    A[Device sends DHCPDISCOVER] --> B{MAC exists in MAC status?}

    B -->|No| C[Create MAC row with first_seen; other fields null]
    C --> D[Offer IP from main pool]
    D --> E[Create IP lease row]
    E --> F[Apply DNS hijack and HP5130 ACL block]
    F --> G[DHCP ACK; captive portal appears]

    B -->|Yes| H{internet_blocked = true?}

    H -->|Yes| I{Active blocked-pool lease exists?}
    I -->|Yes| J[Renew blocked-pool lease]
    I -->|No| K[Expire active non-blocked lease if present]
    K --> L[Offer blocked-pool IP]
    L --> M[Create or renew blocked lease]
    M --> N[DHCP ACK]

    H -->|No| O{Active non-blocked lease exists?}
    O -->|Yes| P[Renew non-blocked lease]
    O -->|No| Q[Expire active blocked lease if present]
    Q --> R[Offer non-blocked-pool IP]
    R --> S[Evaluate Assigned VLAN, validation, block state]
    S --> T{internet_accessible true?}
    T -->|Yes| U[No hijack/block required]
    T -->|No or null| V[Apply DNS hijack and HP5130 ACL block]
    U --> W[DHCP ACK]
    V --> W
DHCPREQUEST renewal rule

If a device tries to renew an IP from the wrong pool, Kea should expire the existing lease and issue a DHCP NAK.

Examples:

device has a non-blocked-pool IP but internet_blocked = true;
device has a blocked-pool IP but internet_blocked is no longer true.

The NAK should cause the device to issue a new DHCPDISCOVER, after which the normal DHCPDISCOVER flow applies.

7. Wi-Fi Registration Flow

When an unregistered device connects over Wi-Fi:

Kea creates or updates lease information.
DNS hijack and HP5130 ACL block are applied.
The device is redirected to the captive portal.
The user submits:
first name;
second name;
email;
telephone number;
device type;
user agreement.
The portal creates or updates the user record.
The portal records the device type.
The selected VLAN is the VLAN the device is currently connected to.
The system checks connection-access policy.
If approval is not required:
Assigned VLAN is set;
ownership row is created in MAC address users;
access can be granted once validation and block-removal conditions are satisfied.
If approval is required:
the admin receives an approval email;
Assigned VLAN remains null until the admin decides.
8. Wired Ethernet Registration Flow

For Ethernet devices:

If RADIUS already has a MAC/VLAN pair, the HP5130 assigns the device to that VLAN.
DHCP then proceeds as with Wi-Fi.
If the device is unknown, it initially lands in the captive/blocked environment.
During registration, the user or admin must select a VLAN from VLANs where Wired allowed = true.
When an admin assigns a wired device:
Assigned VLAN is set;
the RADIUS table is updated;
hp5130-replug.sh is queued for the port;
no immediate DNS/ACL unblock is required while the device remains on VLAN 250 or another captive VLAN.
9. Captive Portal Behaviour

The captive portal root page attempts to identify the client MAC address.

flowchart TD
    A[Open captive portal root] --> B{Can determine client MAC?}

    B -->|No| C[Redirect to HTTPS login page]
    C --> D[Email + password]
    D --> E{Password correct?}
    E -->|No| F[Retry or forgot-password flow]
    E -->|Yes| G[MFA setup or MFA challenge]
    G --> H[Redirect to user_home]

    B -->|Yes| I{Active ownership row exists?}
    I -->|No| J[Show device registration form]
    I -->|Yes| K{VLAN requires password and ownership not validated?}
    K -->|Yes| L[Ask user to set or enter password]
    L --> M[Set ownership_validated = true on success]
    K -->|No| N[Evaluate access state]
    M --> N

    N --> O{internet_blocked = true?}
    O -->|Yes| P[Show blocked-device message and admin contact link]
    O -->|No| Q{Assigned VLAN}
    Q -->|Null| R[Show pending admin review message]
    Q -->|Different from current VLAN| S[Tell user to reconnect to assigned VLAN]
    Q -->|Matches current VLAN| T{internet_accessible}
    T -->|true| U[Show full-access message and user_home link]
    T -->|false| V[Show refused or unavailable access message]
    T -->|null| W[Remove hijack/ACL if eligible, then set accessible true]
Password-required VLANs

If a VLAN has Password required = true, full access requires ownership_validated = true.

If the user has no password set:

send them a password setup email;
display a message telling them to set a password;
poll until the password exists;
then prompt for the password.

If the password is correct, set ownership_validated = true.

10. Granting Full Access

Full access is granted by removing all active enforcement for the device’s current IP:

remove Pi iptables DNS hijack rule;
set DNS hijacked = false in IP status;
remove HP5130 ACL block for the IP on the relevant VLAN;
only after successful synchronous removal, set internet_accessible = true.

This ordering is important: internet_accessible = true must mean that full access is actually in place.

11. Blocking and Unblocking
11.1 Blocking a device

When a device is blocked:

set internet_accessible = null;
set internet_blocked = true;
if the device has a non-expired lease:
apply DNS hijack;
set DNS hijacked = true;
apply HP5130 ACL block;
on the next DHCP renewal, the device should be moved into the blocked pool.
11.2 Unblocking a device

When a device is unblocked:

set internet_blocked = null or false;
inspect active leases;
if the device is on its assigned VLAN, validated if necessary, and not in the blocked pool:
remove DNS hijack;
remove HP5130 ACL block;
set internet_accessible = true;
if it is on the wrong VLAN or not validated:
keep enforcement in place;
set internet_accessible = false;
if it currently has a blocked-pool lease:
tell the user to disconnect and reconnect so Kea can issue a non-blocked-pool lease.

For Ethernet devices, also queue hp5130-replug.sh so the port can be reassigned correctly.

12. Admin Dashboard

The dashboard has three main sections.

12.1 Unregistered devices

Shows MAC addresses that do not currently have an active ownership row.

For each device, display:

MAC address;
first-seen time;
most recent IP address;
lease start and expiry;
current VLAN where known.

The admin can assign a device to a user and VLAN.

For Wi-Fi devices:

the default VLAN is the current Wi-Fi VLAN;
the admin may choose another VLAN except VLAN 250;
if chosen VLAN differs from the current VLAN, set internet_accessible = false;
if chosen VLAN matches current VLAN, remove hijack/ACL synchronously and then set internet_accessible = true.

For Ethernet devices:

no VLAN is preselected;
admin must choose a wired-allowed VLAN;
update Assigned VLAN;
update RADIUS table;
queue hp5130-replug.sh.
12.2 Users

Shows all users with:

email;
full name;
registration date;
expiry date;
owned MAC addresses;
current IPs;
connectivity status;
number of owned devices;
connection VLAN permissions;
adoption VLAN permissions.

Display convention for VLAN permissions:

Style	Meaning
Italic	Allowed by email-domain policy.
Bold	Allowed by user-specific override.
Strikethrough	User-specific override requires approval.
Combined styles	Multiple policy effects apply.

Each user has:

edit button;
block/unblock button.

Blocking a user blocks all actively owned devices.
Unblocking a user applies the normal device-unblock logic to each active device.

12.3 Registered devices

Shows ownership-history rows from MAC address users.

Rows with end date/time != null are greyed out.

For each row, show:

user;
MAC address;
current or latest IP;
lease start and expiry;
device type;
first-seen time;
connectivity status.

For active rows, provide:

block;
unblock;
reassign;
unregister.
13. Reassignment, Unregistration, and Abandonment
13.1 Reassign device

When an admin reassigns a device:

set the old ownership row’s end date/time to now;
create a new ownership row for the new user;
keep the MAC address history intact;
update the registered-devices and users views via AJAX.
13.2 Unregister device

When an admin unregisters a device:

if the device currently has full access and an active lease, apply DNS hijack and HP5130 ACL block;
clear from MAC address status:
internet_accessible;
Assigned VLAN;
device type;
ownership_validated;
delete any RADIUS row for the MAC;
close the active ownership row in MAC address users;
move the device from registered to unregistered in the UI.
13.3 User abandons device

When a user abandons a device:

warn that the device will lose internet access;
if confirmed and the device has an active lease:
apply DNS hijack;
apply HP5130 ACL block;
set DNS hijacked = true;
close the ownership row;
reset MAC status fields;
set first_seen to the current time so it appears as newly unregistered.
14. User Home Page

The user home page allows a logged-in user to:

edit name and telephone number;
change password;
view owned devices;
abandon owned devices;
view adoptable unregistered devices.

For unregistered devices:

if the user can adopt the device’s VLAN without approval, show the MAC address;
if admin approval is required, show only the first-seen date/time;
adoption permissions are calculated using the domain and user adoption policy tables.

When the user adopts a device:

flowchart TD
    A[User clicks Adopt] --> B{Approval required?}
    B -->|No| C[Assign MAC to user]
    C --> D[Set Assigned VLAN]
    D --> E[Remove DNS hijack and ACL if eligible]
    E --> F[Set internet_accessible = true]

    B -->|Yes| G[Email admin approval request]
    G --> H[Admin reviews]
    H -->|Approve| C
    H -->|Decline| I[Keep captive or blocked]
15. Admin Review Links

Admin approval pages are used for registration or adoption requests requiring review.

The admin can:

accept access to the VLAN the device is currently connected to;
decline the request;
decline the requested VLAN but assign a different VLAN;
provide an optional explanation.

If a different VLAN is assigned, the user is told to reconnect to the assigned VLAN.

16. Subnet and Pool Changes

When a VLAN subnet prefix changes, the system must update:

main pool range;
blocked pool range;
DNS hijack ranges;
HP5130 ACL block ranges.

If the subnet becomes smaller:

active blocked-pool IPs may need individual DNS hijack and ACL rules.

If the subnet becomes larger:

devices with internet_accessible = true that now fall inside the blocked pool need temporary manual allow overrides;
once their leases expire and they receive main-pool IPs, those overrides should be removed.
17. Expired Lease Cleanup

A background cleanup process runs every few seconds.

It should:

find expired leases in IP status;
remove DNS hijacks for expired IPs;
remove HP5130 ACL blocks for expired IPs;
set DNS hijacked = false;
for MACs with no active leases, set internet_accessible = null.
flowchart TD
    A[Periodic lease cleanup] --> B[Find expired leases]
    B --> C{DNS hijacked or ACL block exists?}
    C -->|Yes| D[Remove DNS hijack and HP5130 ACL]
    C -->|No| E[No network cleanup needed]
    D --> F[Set DNS hijacked = false]
    E --> G[Check MAC active leases]
    F --> G
    G --> H{MAC has active lease?}
    H -->|No| I[Set internet_accessible = null]
    H -->|Yes| J[Leave MAC access state unchanged]
18. Multi-Premises Synchronisation

The system supports multiple local premises and a central server.

Each premise has its own local database and enforcement infrastructure. The central server stores cross-site registration and block state.

18.1 Registration propagation

When a device registers at premise A:

premise A stores the local registration;
premise A queues a registration message to the central server;
the queued message is retried until acknowledged;
the central server stores the registration and records that the device exists at premise A.

When the device later appears at premise B:

premise B does not recognise the MAC locally;
premise B asks the central server;
the central server returns registration details and block status;
premise B stores the registration locally;
the central server records that the device is now known at premises A and B.
18.2 Block propagation

When an admin blocks a device at premise A:

premise A applies local DNS hijacks and ACL blocks;
premise A sets internet_blocked = true;
premise A queues a block message to the central server;
the central server fans out the block to other premises where the device is registered;
other premises apply the block if the device has an active lease;
if the device has no active lease, internet_blocked = true ensures it will be placed in the blocked pool when it next connects.

The central server does not send the block back to the originating premise, and does not send it to premises where the device is not registered.

18.3 Device arrives at a new premise while blocked

If the device connects at premise C and the central server is reachable:

premise C asks the central server about the MAC;
central server returns registration details and blocked status;
premise C stores the registration;
premise C keeps captive/block enforcement in place;
premise C sets internet_blocked = true.

If the central server is unavailable:

premise C queues the registration query/update;
the device remains captive or blocked locally;
once the central server responds, premise C applies the returned blocked state.
18.4 Deregistration propagation

When a device is deregistered because of user rejection, admin deletion, timeout, or abandonment:

the central device entry is deleted or marked inactive;
the central server fans out the deregistration to all premises where the device is known;
each premise:
clears internet_accessible;
clears Assigned VLAN;
clears device type;
clears ownership_validated;
deletes any RADIUS row;
closes the active ownership row in MAC address users.
18.5 Multi-site sync diagram
sequenceDiagram
    participant A as Premise A
    participant C as Central Server
    participant B as Premise B
    participant X as Premise C

    A->>A: Register device locally
    A->>C: Queue registration update
    C-->>A: Acknowledge registration

    B->>C: Unknown MAC; request registration
    C-->>B: Return registration details
    B->>B: Store local registration
    B->>C: Confirm device now present at B

    A->>A: Admin blocks device
    A->>C: Queue block instruction
    C->>B: Fan out block instruction
    B->>B: Apply block if active lease exists
    B-->>C: Confirm block applied

    X->>C: Unknown MAC; request registration
    C-->>X: Return registration + blocked status
    X->>X: Store registration and keep blocked
19. Operational Principles
The database is the source of truth.
internet_accessible = true must only be set after enforcement has actually been removed.
Blocking should be immediate for active leases and persistent for future leases.
Unblocking may require the user to reconnect if the device currently has a blocked-pool IP.
User-specific VLAN rules override email-domain rules.
Ownership history must be preserved rather than overwritten.
Wired assignment requires RADIUS updates and usually a port replug.
Expired leases must be cleaned up so old hijacks and ACLs do not affect future devices.
Multi-site messages must be queued and retried until acknowledged.
Central-server state must include registrations, blocked devices, and blocked users so that premises remain synchronised.
20. Main End-to-End Flow
flowchart TD
    A[Device connects] --> B[DHCP handled by Kea]
    B --> C{Known MAC?}
    C -->|No| D[Create MAC row and captive lease]
    C -->|Yes| E[Evaluate block and lease state]
    D --> F[Captive portal]
    E --> F

    F --> G{Registered owner?}
    G -->|No| H[User registration or admin assignment]
    G -->|Yes| I[Check VLAN, validation, block state]

    H --> J{Approval required?}
    J -->|Yes| K[Admin review]
    J -->|No| L[Assign VLAN and owner]

    K -->|Approve| L
    K -->|Decline or assign different VLAN| M[Keep captive or tell user correct VLAN]

    L --> I
    I --> N{Eligible for full access?}
    N -->|No| O[Keep DNS hijack / ACL block]
    N -->|Yes| P[Remove DNS hijack and ACL synchronously]
    P --> Q[Set internet_accessible = true]