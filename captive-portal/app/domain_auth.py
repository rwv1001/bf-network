"""
domain_auth.py — verify user passwords against the identity provider of email
domains the operator OWNS (e.g. english.op.org hosted on Microsoft 365).

Passwords for domains you do NOT own can never be verified — no identity
provider exposes credential checks to third parties. Those users must use a
BF-Network password instead.

Configuration (environment):

    DOMAIN_AUTH_PROVIDERS   Semicolon-separated list of owned domains:
                                domain:tenant_id:client_id[;domain2:...]
                            e.g.
                                english.op.org:11111111-2222-3333-4444-555555555555:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

    tenant_id   Entra ID (Azure AD) Directory/tenant ID for the domain.
    client_id   An Entra app registration with "Allow public client flows"
                enabled (Authentication blade). No secret is needed — password
                verification uses the OAuth2 Resource Owner Password
                Credentials (ROPC) flow.

Caveats of ROPC (surfaced to the user as helpful error messages):
  - Accounts requiring MFA / conditional access cannot be verified this way.
  - Federated or personal Microsoft accounts are not supported.
"""

import logging
import os
import threading

import requests

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_cached_raw = None
_cached_providers = {}


def _providers() -> dict:
    """Parse DOMAIN_AUTH_PROVIDERS into {domain: {tenant_id, client_id}}."""
    global _cached_raw, _cached_providers
    raw = (os.getenv('DOMAIN_AUTH_PROVIDERS') or '').strip()
    with _lock:
        if raw == _cached_raw:
            return _cached_providers
        providers = {}
        for entry in raw.split(';'):
            entry = entry.strip()
            if not entry:
                continue
            parts = [p.strip() for p in entry.split(':')]
            if len(parts) < 3 or not all(parts[:3]):
                logger.warning("DOMAIN_AUTH_PROVIDERS: ignoring malformed entry %r "
                               "(expected domain:tenant_id:client_id)", entry)
                continue
            providers[parts[0].lower()] = {
                'domain': parts[0].lower(),
                'tenant_id': parts[1],
                'client_id': parts[2],
            }
        _cached_raw = raw
        _cached_providers = providers
        return providers


def get_provider_for_email(email: str):
    """Return the provider dict for this email's domain, or None."""
    email = (email or '').strip().lower()
    if '@' not in email:
        return None
    return _providers().get(email.split('@', 1)[1])


def verify_domain_credentials(email: str, password: str):
    """Verify email+password against the owned domain's identity provider.

    Returns (ok: bool, error_message: str | None). ok=False with
    error_message=None means "wrong password"; a message indicates a
    condition worth telling the user about (e.g. MFA blocks verification).
    """
    provider = get_provider_for_email(email)
    if not provider:
        return False, 'This email domain is not configured for email-password sign-in.'

    url = f"https://login.microsoftonline.com/{provider['tenant_id']}/oauth2/v2.0/token"
    try:
        resp = requests.post(
            url,
            data={
                'grant_type': 'password',
                'client_id': provider['client_id'],
                'username': email,
                'password': password,
                'scope': 'openid',
            },
            timeout=10,
        )
    except Exception as exc:
        logger.error("domain auth: token request failed for %s: %s", email, exc)
        return False, 'Could not reach the sign-in service. Please try again or use a BF-Network password.'

    if resp.status_code == 200:
        return True, None

    try:
        body = resp.json()
    except Exception:
        body = {}
    desc = body.get('error_description', '') or ''
    logger.info("domain auth: verification failed for %s: %s", email, desc.split('\n')[0][:200])

    # AADSTS error codes that are NOT a simple wrong password
    if 'AADSTS50076' in desc or 'AADSTS50079' in desc or 'AADSTS53003' in desc:
        return False, ('Your account requires multi-factor authentication, so your email '
                       'password cannot be verified here. Please use a BF-Network password instead.')
    if 'AADSTS50034' in desc:
        return False, 'No account with this email address was found.'
    if 'AADSTS50057' in desc:
        return False, 'This account is disabled. Please contact the administrator.'
    if 'AADSTS50055' in desc:
        return False, 'Your email password has expired. Please reset it, then try again.'
    if 'AADSTS7000218' in desc or 'AADSTS700016' in desc:
        logger.error("domain auth: app registration misconfigured for %s "
                     "(enable 'Allow public client flows' / check client_id)", provider['domain'])
        return False, 'Email-password sign-in is misconfigured. Please use a BF-Network password or contact the administrator.'

    # AADSTS50126 = invalid username or password
    return False, None
