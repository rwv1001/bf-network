"""
Pi-Hole v6 API client.

All Pi-Hole API calls originate server-side.  Session tokens are stored in
Redis so all gunicorn workers share a single Pi-Hole session.
"""

import logging
import os
import threading
import time

import requests

logger = logging.getLogger(__name__)

_PIHOLE_SID_KEY  = 'pihole:sid'
_PIHOLE_EXP_KEY  = 'pihole:expires'

_pihole_redis_lock   = threading.Lock()
_pihole_redis_client = None


def pihole_redis():
    """Return a Redis client (lazily created, shared within the process)."""
    global _pihole_redis_client
    if _pihole_redis_client is None:
        with _pihole_redis_lock:
            if _pihole_redis_client is None:
                import redis as _redis_module
                url = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
                _pihole_redis_client = _redis_module.from_url(url, decode_responses=True)
    return _pihole_redis_client


def _pihole_base() -> str:
    host = os.getenv('PIHOLE_HOST', os.environ.get('PORTAL_IP', '127.0.0.1'))
    port = os.getenv('PIHOLE_PORT', '8055')
    return f'http://{host}:{port}'


def _pihole_auth(old_sid: str = None):
    """Authenticate with Pi-Hole, optionally logging out old_sid first."""
    password = os.getenv('PIHOLE_WEBPASSWORD', '')
    base = _pihole_base()
    if old_sid:
        try:
            requests.delete(f'{base}/api/auth',
                            headers={'X-FTL-SID': old_sid}, timeout=3)
        except Exception:
            pass
    try:
        r = requests.post(f'{base}/api/auth', json={'password': password}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            sid = data.get('session', {}).get('sid')
            validity = int(data.get('session', {}).get('validity', 300))
            expires = time.time() + validity - 30
            rdb = pihole_redis()
            rdb.set(_PIHOLE_SID_KEY, sid, ex=int(validity))
            rdb.set(_PIHOLE_EXP_KEY, str(expires), ex=int(validity))
            return sid
    except Exception as exc:
        logger.warning('Pi-Hole auth failed: %s', exc)
    return None


def _pihole_headers():
    """Return auth headers, using a Redis-shared session across all workers."""
    try:
        rdb = pihole_redis()
        sid = rdb.get(_PIHOLE_SID_KEY)
        exp = rdb.get(_PIHOLE_EXP_KEY)
        if sid and exp and time.time() < float(exp):
            return {'X-FTL-SID': sid}
        lock = rdb.set('pihole:auth_lock', '1', nx=True, ex=10)
        if lock:
            sid = _pihole_auth(old_sid=sid)
        else:
            time.sleep(0.5)
            sid = rdb.get(_PIHOLE_SID_KEY)
    except Exception as exc:
        logger.warning('Pi-Hole Redis session lookup failed: %s', exc)
        sid = _pihole_auth()
    return {'X-FTL-SID': sid} if sid else None


def _pihole_retry(fn, path: str, **kwargs):
    """Call fn(url, headers, **kwargs), retry once on 401."""
    hdrs = _pihole_headers()
    if hdrs is None:
        return None
    try:
        r = fn(f'{_pihole_base()}{path}', headers=hdrs, timeout=8, **kwargs)
        if r.status_code == 401:
            try:
                rdb = pihole_redis()
                old_sid = rdb.get(_PIHOLE_SID_KEY)
                rdb.delete(_PIHOLE_SID_KEY, _PIHOLE_EXP_KEY)
            except Exception:
                old_sid = None
            hdrs = _pihole_headers()
            if hdrs is None:
                return None
            r = fn(f'{_pihole_base()}{path}', headers=hdrs, timeout=8, **kwargs)
        return r
    except Exception as exc:
        logger.warning('Pi-Hole request to %s failed: %s', path, exc)
        return None


def pihole_get(path: str):
    r = _pihole_retry(requests.get, path)
    if r and r.ok:
        return r.json()
    return None


def pihole_post(path: str, body=None):
    r = _pihole_retry(requests.post, path, json=body)
    if r and r.ok:
        return r.json() if r.content else {}
    return None


def pihole_delete(path: str) -> bool:
    r = _pihole_retry(requests.delete, path)
    return r is not None and r.status_code in (200, 204)


def pihole_put(path: str, body=None):
    r = _pihole_retry(requests.put, path, json=body)
    if r and r.ok:
        return r.json() if r.content else {}
    return None
