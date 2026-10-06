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
                enabled (Authentication blade). No secret is needed.

Two flows:
  - ROPC (password grant) for accounts that do not require MFA.
  - Device-code login for accounts that do. Microsoft will not accept a
    password alone once MFA or conditional access applies (AADSTS50076 /
    AADSTS50079 / AADSTS53003). The user opens the verification URL, enters
    the code, and completes MFA there. The portal then polls
    poll_device_login() until the token arrives.

The app registration must allow public client flows. Device code also needs
"Allow public client flows" and the delegated openid permission.
"""

import logging
import os
import secrets
import sqlite3
import threading
import time

import requests

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_cached_raw = None
_cached_providers = {}

_MFA_CODES = ('AADSTS50076', 'AADSTS50079', 'AADSTS53003')

# The long-lived Microsoft device_code is kept server-side, keyed by an opaque
# handle stored in the Flask session — it never reaches the browser.
_PENDING_DB_PATH = os.getenv('DOMAIN_AUTH_PENDING_DB', '/tmp/domain-auth-pending.sqlite3')


def _pending_db():
    conn = sqlite3.connect(_PENDING_DB_PATH, timeout=5)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_device_login (
            handle TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            device_code TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )
    conn.execute('DELETE FROM pending_device_login WHERE expires_at <= ?', (int(time.time()),))
    conn.commit()
    try:
        os.chmod(_PENDING_DB_PATH, 0o600)
    except OSError:
        pass
    return conn


def store_pending_device_login(email: str, device_code: str, expires_in: int) -> str:
    """Store a device_code server-side; returns the opaque handle."""
    email = (email or '').strip().lower()
    device_code = (device_code or '').strip()
    if not email or not device_code:
        raise ValueError('email and device_code are required')
    handle = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + max(60, min(int(expires_in or 900), 3600))
    with _pending_db() as conn:
        conn.execute(
            'INSERT INTO pending_device_login(handle, email, device_code, expires_at) VALUES (?, ?, ?, ?)',
            (handle, email, device_code, expires_at),
        )
    return handle


def delete_pending_device_login(handle: str) -> None:
    if not handle:
        return
    with _pending_db() as conn:
        conn.execute('DELETE FROM pending_device_login WHERE handle = ?', (handle,))


def poll_pending_device_login(email: str, handle: str):
    """Poll a stored device-code flow without exposing device_code to the browser."""
    email = (email or '').strip().lower()
    handle = (handle or '').strip()
    if not email or not handle:
        return 'error', 'Microsoft sign-in is no longer valid. Please start again.'

    with _pending_db() as conn:
        row = conn.execute(
            'SELECT email, device_code, expires_at FROM pending_device_login WHERE handle = ?',
            (handle,),
        ).fetchone()
    if not row:
        return 'error', 'Microsoft sign-in is no longer valid. Please start again.'

    stored_email, device_code, expires_at = row
    if stored_email != email or int(expires_at) <= int(time.time()):
        delete_pending_device_login(handle)
        return 'error', 'Microsoft sign-in has expired. Please start again.'

    status, error = poll_device_login(email, device_code)
    if status != 'pending':
        delete_pending_device_login(handle)
    return status, error


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


def _token_url(provider: dict) -> str:
    return f"https://login.microsoftonline.com/{provider['tenant_id']}/oauth2/v2.0/token"


def _identity_matches(email: str, token_body: dict) -> bool:
    """The completed login must be for the address the user typed."""
    wanted = (email or '').strip().lower()
    id_token = token_body.get('id_token') or ''
    claimed = ''
    if id_token.count('.') == 2:
        try:
            import base64
            import json
            payload = id_token.split('.')[1]
            payload += '=' * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload.encode()))
            claimed = (claims.get('preferred_username') or claims.get('email') or '').lower()
        except Exception as exc:
            logger.warning("domain auth: could not read id_token for %s: %s", email, exc)
    if claimed and claimed != wanted:
        logger.info("domain auth: token identity %s does not match %s", claimed, wanted)
        return False
    return True


def verify_domain_credentials(email: str, password: str):
    """Verify email+password against the owned domain's identity provider.

    Returns (ok: bool, error_message: str | None). ok=False with
    error_message=None means "wrong password"; a message indicates a
    condition worth telling the user about.

    MFA cannot be completed in this call. On AADSTS50076/50079/53003 the
    message tells the caller to start start_device_login() instead.
    """
    provider = get_provider_for_email(email)
    if not provider:
        return False, 'This email domain is not configured for email-password sign-in.'

    try:
        resp = requests.post(
            _token_url(provider),
            data={
                'grant_type': 'password',
                'client_id': provider['client_id'],
                'username': email,
                'password': password,
                'scope': 'openid profile email',
            },
            timeout=10,
        )
    except Exception as exc:
        logger.error("domain auth: token request failed for %s: %s", email, exc)
        return False, 'Could not reach the sign-in service. Please try again or use a BF-Network password.'

    if resp.status_code == 200:
        body = {}
        try:
            body = resp.json()
        except Exception:
            body = {}
        if not _identity_matches(email, body):
            return False, 'The signed-in account does not match this email address.'
        return True, None

    try:
        body = resp.json()
    except Exception:
        body = {}
    desc = body.get('error_description', '') or ''
    logger.info("domain auth: verification failed for %s: %s", email, desc.split('\n')[0][:200])

    if any(code in desc for code in _MFA_CODES):
        return False, (
            'This account requires multi-factor authentication. '
            'Enter the code at the Microsoft sign-in page to continue.'
        )
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

    return False, None


def start_device_login(email: str):
    """Begin a device-code login that can complete MFA.

    Returns a dict on success:
        user_code, verification_uri, device_code, interval, expires_in, message
    or (None, error_message) on failure.
    """
    provider = get_provider_for_email(email)
    if not provider:
        return None, 'This email domain is not configured for email-password sign-in.'
    try:
        resp = requests.post(
            f"https://login.microsoftonline.com/{provider['tenant_id']}/oauth2/v2.0/devicecode",
            data={
                'client_id': provider['client_id'],
                'scope': 'openid profile email',
            },
            timeout=10,
        )
    except Exception as exc:
        logger.error("domain auth: device-code request failed for %s: %s", email, exc)
        return None, 'Could not reach the sign-in service. Please try again or use a BF-Network password.'
    if resp.status_code != 200:
        logger.error("domain auth: device-code start HTTP %s for %s: %s",
                     resp.status_code, email, resp.text[:300])
        return None, 'Email sign-in could not be started. Please use a BF-Network password or contact the administrator.'
    body = resp.json()
    return {
        'email': (email or '').strip().lower(),
        'user_code': body.get('user_code'),
        'verification_uri': body.get('verification_uri'),
        'device_code': body.get('device_code'),
        'interval': int(body.get('interval') or 5),
        'expires_in': int(body.get('expires_in') or 900),
        'message': body.get('message') or '',
    }, None


def poll_device_login(email: str, device_code: str):
    """Poll a device-code login started by start_device_login().

    Returns (status, error_message). status is 'ok', 'pending', or 'error'.
    Call again while status is 'pending'. Do not poll faster than the
    interval returned by start_device_login().
    """
    provider = get_provider_for_email(email)
    if not provider or not device_code:
        return 'error', 'Email sign-in is no longer valid. Please start again.'
    try:
        resp = requests.post(
            _token_url(provider),
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'client_id': provider['client_id'],
                'device_code': device_code,
            },
            timeout=10,
        )
    except Exception as exc:
        logger.error("domain auth: device-code poll failed for %s: %s", email, exc)
        return 'error', 'Could not reach the sign-in service. Please try again.'
    if resp.status_code == 200:
        body = resp.json()
        if not _identity_matches(email, body):
            return 'error', 'The signed-in account does not match this email address.'
        return 'ok', None
    try:
        body = resp.json()
    except Exception:
        body = {}
    err = body.get('error') or ''
    if err == 'authorization_pending':
        return 'pending', None
    if err == 'slow_down':
        return 'pending', None
    if err == 'expired_token':
        return 'error', 'The sign-in code expired. Please start again.'
    if err == 'authorization_declined':
        return 'error', 'Sign-in was cancelled.'
    logger.info("domain auth: device-code poll failed for %s: %s", email, err)
    return 'error', 'Email sign-in failed. Please try again or use a BF-Network password.'
