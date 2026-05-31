"""
User / domain-policy helpers.

Covers:
- Domain policy loading and resolution
- Effective VLAN set calculation (allowed + adoptable)
- VLAN display item formatting for the admin dashboard
- VLAN override form parsing
- CSV import helpers
"""

import logging
import re

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------

def email_domain(email: str) -> str:
    """Return the lowercase domain part of an email address."""
    if not email or '@' not in email:
        return ''
    return email.split('@', 1)[1].strip().lower()


def parse_allowed_vlans(raw: str) -> set:
    """Parse a comma-separated VLAN ID string into a set of ints."""
    if not raw:
        return set()
    allowed = set()
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry:
            continue
        try:
            allowed.add(int(entry))
        except ValueError:
            continue
    return allowed


def format_allowed_vlans(vlans) -> str:
    """Serialise a set/list of VLAN IDs to a comma-separated string."""
    if not vlans:
        return ''
    return ','.join(str(vlan) for vlan in sorted(vlans))


# ---------------------------------------------------------------------------
# Domain policy helpers
# ---------------------------------------------------------------------------

def load_domain_policy_map() -> dict:
    """Return {domain_str: DomainPolicy} for all rows in domain_policies."""
    from models import DomainPolicy
    policies = DomainPolicy.query.all()
    return {policy.domain.lower(): policy for policy in policies}


def get_domain_policy_for_user(user, domain_policy_map: dict = None):
    """Return the DomainPolicy for a user's email domain, or None."""
    if not user or not user.email:
        return None
    if domain_policy_map is None:
        domain_policy_map = load_domain_policy_map()
    return domain_policy_map.get(email_domain(user.email))


def effective_vlan_sets(user, domain_policy) -> tuple:
    """
    Return (effective_allowed, effective_adoptable, domain_allowed_only, domain_adoptable_only).
    User-specific overrides take precedence over domain policy.
    """
    domain_allowed = parse_allowed_vlans(domain_policy.allowed_vlans) if domain_policy else set()
    domain_adoptable = parse_allowed_vlans(domain_policy.adoptable_vlans) if domain_policy else set()

    user_allow = parse_allowed_vlans(user.allowed_vlans_override)
    user_deny = parse_allowed_vlans(user.allowed_vlans_deny)
    user_adopt_allow = parse_allowed_vlans(user.adoptable_vlans_override)
    user_adopt_deny = parse_allowed_vlans(user.adoptable_vlans_deny)

    eff_allowed = (domain_allowed | user_allow) - user_deny
    eff_adoptable = (domain_adoptable | user_adopt_allow) - user_adopt_deny

    domain_allowed_only = domain_allowed - user_allow - user_deny
    domain_adoptable_only = domain_adoptable - user_adopt_allow - user_adopt_deny

    return eff_allowed, eff_adoptable, domain_allowed_only, domain_adoptable_only


def get_effective_vlans_for_user(user, domain_policy_map: dict = None) -> tuple:
    """Return (effective_allowed, effective_adoptable) for a user."""
    domain_policy = get_domain_policy_for_user(user, domain_policy_map)
    eff_allowed, eff_adoptable, _, _ = effective_vlan_sets(user, domain_policy)
    return eff_allowed, eff_adoptable


# ---------------------------------------------------------------------------
# VLAN display item formatting (admin dashboard)
# ---------------------------------------------------------------------------

def format_vlan_display_items(vlans, domain_based: set, denied: set,
                               user_override: set, vlan_map: dict) -> list:
    """
    Return a list of dicts describing each VLAN for display in the admin UI.
    Each dict has: label, domain_based, denied, user_override.
    """
    from core.vlan_utils import label_for_vlan
    items = []
    denied = denied or set()
    user_override = user_override or set()
    for vlan_id in sorted(vlans):
        items.append({
            'label': label_for_vlan(vlan_id, vlan_map),
            'domain_based': vlan_id in domain_based,
            'denied': vlan_id in denied,
            'user_override': vlan_id in user_override,
        })
    return items


def format_vlan_items_text(items: list) -> str:
    """Return a comma-separated string of non-denied VLAN labels."""
    if not items:
        return ''
    return ', '.join(item['label'] for item in items if not item.get('denied'))


def allowed_vlans_display_items(user, vlan_map: dict, domain_policy,
                                 include_denied: bool = False) -> list:
    eff_allowed, _, _, _ = effective_vlan_sets(user, domain_policy)
    user_allow = parse_allowed_vlans(user.allowed_vlans_override)
    user_deny = parse_allowed_vlans(user.allowed_vlans_deny)
    domain_allowed = parse_allowed_vlans(domain_policy.allowed_vlans) if domain_policy else set()
    denied_vlans = user_deny if include_denied else set()
    display_vlans = eff_allowed | denied_vlans
    if not display_vlans:
        return []
    return format_vlan_display_items(display_vlans, domain_allowed, denied_vlans, user_allow, vlan_map)


def adoptable_vlans_display_items(user, vlan_map: dict, domain_policy,
                                   include_denied: bool = False) -> list:
    _, eff_adoptable, _, _ = effective_vlan_sets(user, domain_policy)
    user_allow = parse_allowed_vlans(user.adoptable_vlans_override)
    user_deny = parse_allowed_vlans(user.adoptable_vlans_deny)
    domain_adoptable = parse_allowed_vlans(domain_policy.adoptable_vlans) if domain_policy else set()
    denied_vlans = user_deny if include_denied else set()
    display_vlans = eff_adoptable | denied_vlans
    if not display_vlans:
        return []
    return format_vlan_display_items(display_vlans, domain_adoptable, denied_vlans, user_allow, vlan_map)


# ---------------------------------------------------------------------------
# VLAN override form parsing (admin add/edit user)
# ---------------------------------------------------------------------------

def parse_vlan_override_form(vlan_map: dict, prefix: str) -> tuple:
    """
    Parse VLAN allow/deny radio buttons from a Flask request form.
    Returns (allow_set, deny_set).
    """
    from flask import request
    allow = set()
    deny = set()
    for status, vlan_id in vlan_map.items():
        if status in {'unregistered', 'restricted'}:
            continue
        value = (request.form.get(f'{prefix}_{vlan_id}') or '').strip().lower()
        if value == 'allow':
            allow.add(vlan_id)
        elif value == 'deny':
            deny.add(vlan_id)
    return allow, deny


def default_vlan_for_user(allowed_vlans, vlan_map: dict):
    """Return the lowest allowed VLAN ID for a user, or None."""
    if allowed_vlans:
        return sorted(allowed_vlans)[0]
    return None


# ---------------------------------------------------------------------------
# CSV import helpers
# ---------------------------------------------------------------------------

def normalize_csv_header(value) -> str:
    if value is None:
        return ''
    return re.sub(r'\s+', ' ', str(value)).strip().lower()


def parse_csv_bool(value):
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text in {'y', 'yes', '1', 'true', 'allow', 'allowed'}:
        return True
    if text in {'n', 'no', '0', 'false', 'deny', 'denied'}:
        return False
    return None


def csv_template_fields(vlan_map: dict) -> tuple:
    """Return (base_fields, vlan_fields) for the CSV import template."""
    from core.vlan_utils import get_vlan_entries
    base_fields = [
        ('email', 'Email'),
        ('first_name', 'First Name'),
        ('last_name', 'Second Name'),
        ('phone_number', 'Phone Number'),
        ('mac_address', 'MAC Address'),
        ('device_type', 'Device Type'),
        ('vlan_id', 'VLAN ID'),
    ]
    vlan_fields = []
    for entry in get_vlan_entries():
        if entry.status in {'restricted', 'unregistered'}:
            continue
        vlan_id = entry.vlan_id
        if not vlan_id:
            continue
        vlan_fields.append((f'vlan{vlan_id}_allowed', f'VLAN{vlan_id}Allowed'))
        vlan_fields.append((f'vlan{vlan_id}_adoptable', f'VLAN{vlan_id}Adoptable'))
    return base_fields, vlan_fields


def csv_template_example_value(header: str, row_index: int) -> str:
    examples = {
        'Email': ('robert@example.com', 'jane@example.com'),
        'First Name': ('Robert', 'Jane'),
        'Second Name': ('Verrill', 'Doe'),
        'Phone Number': ('555-0100', '555-0199'),
        'MAC Address': ('AA:BB:CC:DD:EE:FF', ''),
        'Device Type': ('laptop', 'phone'),
        'VLAN ID': ('20', '10'),
    }
    if header in examples:
        return examples[header][row_index]
    match = re.match(r'^VLAN(\d+)(Allowed|Adoptable)$', header)
    if match:
        return 'Y' if row_index == 0 else 'N'
    return ''
