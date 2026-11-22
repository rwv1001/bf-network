"""
Admin — Disaster-recovery backups (docs/RECOVERY.md).

The `backup` container writes OpenPGP-encrypted bundles under
<repo>/backups/bundles: this site's own, plus copies of every other site's and
of bf-central's. This page lists them, lets an admin download one, and asks
the backup container for an immediate run. It cannot decrypt anything: the
recovery private key is not on this server.

Routes:
  GET  /admin/backups                                   list + status
  POST /admin/backups/run                               request a backup now
  GET  /admin/backups/download/<group>/<owner>/<name>   download one bundle
"""

import json
import logging
import os
import re
from datetime import datetime

from flask import Blueprint, abort, flash, redirect, render_template, send_file, url_for
from flask_login import login_required

from core.auth import permission_required

logger = logging.getLogger(__name__)

backups_bp = Blueprint('backups', __name__)

_NAME_RE = re.compile(r'^bfbackup-(site|central)-([A-Za-z0-9._-]+)-(\d{8}T\d{6}Z)\.tar\.gz\.gpg$')
_ID_RE = re.compile(r'^[A-Za-z0-9._-]+$')


def _repo_dir():
    return os.environ.get('GIT_REPO_DIR', '')


def _bundle_root():
    return os.path.join(_repo_dir(), 'backups', 'bundles')


def _queue_dir():
    return os.path.join(_repo_dir(), 'shared', 'backup-queue')


def _list(directory):
    out = []
    try:
        names = sorted((n for n in os.listdir(directory) if _NAME_RE.match(n)), reverse=True)
    except OSError:
        return out
    for name in names:
        try:
            size = os.path.getsize(os.path.join(directory, name))
        except OSError:
            continue
        stamp = _NAME_RE.match(name).group(3)
        try:
            created = datetime.strptime(stamp, '%Y%m%dT%H%M%SZ').strftime('%Y-%m-%d %H:%M UTC')
        except ValueError:
            created = stamp
        out.append({'name': name, 'size': size, 'created': created})
    return out


def _status():
    try:
        with open(os.path.join(_bundle_root(), 'status.json')) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


@backups_bp.route('/backups')
@login_required
@permission_required('manage_firmware')
def admin_backups():
    root = _bundle_root()
    peers = []
    try:
        for owner in sorted(os.listdir(os.path.join(root, 'peers'))):
            if _ID_RE.match(owner) and owner not in ('.', '..'):
                files = _list(os.path.join(root, 'peers', owner))
                if files:
                    peers.append({'site_id': owner, 'files': files})
    except OSError:
        pass
    return render_template(
        'admin_backups.html',
        status=_status(),
        own=_list(os.path.join(root, 'own')),
        peers=peers,
        central=_list(os.path.join(root, 'central')),
        trigger_pending=os.path.exists(os.path.join(_queue_dir(), 'trigger')),
    )


@backups_bp.route('/backups/run', methods=['POST'])
@login_required
@permission_required('manage_firmware')
def run_backup():
    try:
        with open(os.path.join(_queue_dir(), 'trigger'), 'w') as f:
            f.write(datetime.utcnow().isoformat())
        flash('Backup requested. It normally finishes within a minute; reload this page to see it.', 'success')
    except OSError as exc:
        logger.warning('could not queue a backup: %s', exc)
        flash('Could not request a backup: is the backup container running? '
              '(docker compose up -d backup)', 'error')
    return redirect(url_for('admin.backups.admin_backups'))


@backups_bp.route('/backups/download/<group>/<owner>/<name>')
@login_required
@permission_required('manage_firmware')
def download_backup(group, owner, name):
    m = _NAME_RE.match(name)
    if not m or not _ID_RE.match(owner) or owner in ('.', '..'):
        abort(404)
    root = _bundle_root()
    if group == 'own' and m.group(1) == 'site':
        directory = os.path.join(root, 'own')
    elif group == 'peers' and m.group(1) == 'site' and m.group(2) == owner:
        directory = os.path.join(root, 'peers', owner)
    elif group == 'central' and m.group(1) == 'central':
        directory = os.path.join(root, 'central')
    else:
        abort(404)
    path = os.path.join(directory, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, mimetype='application/octet-stream', as_attachment=True, download_name=name)
