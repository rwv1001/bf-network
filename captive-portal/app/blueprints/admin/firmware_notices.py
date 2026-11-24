"""Persistent, non-executing post-firmware-update instructions.

The state file is within the repo's bind-mounted data directory, not a Flask
session: SSE responses and web-container image rebuilds cannot lose notices.
"""
import fcntl
import json
import os
import tempfile
from datetime import datetime, timezone


def _path():
    return os.path.join(os.environ['GIT_REPO_DIR'], 'captive-portal', 'data',
                        'firmware-post-update-notices.json')


def _locked_store(operation, callback):
    path = _path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock_path = path + '.lock'
    with open(lock_path, 'a+') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            with open(path, encoding='utf-8') as handle:
                items = json.load(handle)
                if not isinstance(items, list):
                    raise ValueError('Invalid firmware instructions state')
        except FileNotFoundError:
            items = []
        # Malformed files are NOT silently replaced: instructions must not be lost.
        result = callback(items)
        if operation == 'write':
            fd, temp = tempfile.mkstemp(prefix='.firmware-notices-',
                                        dir=os.path.dirname(path))
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                    json.dump(items, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp, 0o600)
                os.replace(temp, path)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
        return result


def pending_notices():
    return _locked_store('read', lambda items: [i for i in items if not i.get('completed_at')])


def record_step(direction, from_hash, to_hash, manifest):
    """Store one commit's manual instructions, with idempotent replays."""
    section = (manifest or {}).get('post_update' if direction == 'update' else 'post_rollback') or {}
    commands = section.get('commands') or []
    if not isinstance(commands, list) or any(not isinstance(c, str) or not c.strip() for c in commands):
        raise ValueError('post-update commands must be a list of nonempty strings')
    if not commands and not section.get('notes'):
        return False
    key = f'{direction}:{from_hash}:{to_hash}'
    def add(items):
        if any(i.get('id') == key for i in items):
            return False
        items.append({
            'id': key, 'direction': direction,
            'from_commit': from_hash[:7], 'to_commit': to_hash[:7],
            'description': section.get('description') or (manifest or {}).get('description') or 'Firmware update instructions',
            'commands': commands, 'notes': section.get('notes') or '',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'completed_at': None,
        })
        return True
    return _locked_store('write', add)


def record_fallback(direction, from_hash, to_hash, affected):
    """A final stack-rebuild reminder when no commit gave instructions."""
    if not affected:
        return False
    paths = ', '.join(str(x) for x in affected)
    return record_step(direction, from_hash, to_hash, {
        'post_update' if direction == 'update' else 'post_rollback': {
            'description': 'Review the changed Docker Compose stacks',
            'commands': [],
            'notes': ('No commit-specific commands were supplied. Changed stacks: '
                      f'{paths}. Check the services and rebuild/recreate relevant containers '
                      'as needed; do not assume a restart loads changed application code.'),
        }
    })


def acknowledge_notices(ids):
    if not isinstance(ids, list) or any(not isinstance(i, str) for i in ids):
        raise ValueError('Invalid instruction IDs')
    wanted = set(ids)
    def mark(items):
        now = datetime.now(timezone.utc).isoformat()
        count = 0
        for item in items:
            if item.get('id') in wanted and not item.get('completed_at'):
                item['completed_at'] = now
                count += 1
        return count
    return _locked_store('write', mark)
