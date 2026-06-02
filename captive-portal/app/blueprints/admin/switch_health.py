"""
Admin — Switch Health Monitoring (spec section 12 / CODEBASE section 9).

Routes:
  GET  /admin/switch-health          switch health page
  GET  /admin/switch-health/data     AJAX: run health commands on all switches
  GET  /admin/switch-health/rps      return saved RPS settings
  POST /admin/switch-health/rps      save RPS connected flag for a switch
"""

import json
import logging
import os

from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from core.auth import permission_required
from core.switch import get_switch_hosts, run_switch_command

logger = logging.getLogger(__name__)

switch_health_bp = Blueprint('switch_health', __name__)

_SWITCH_RPS_FILE = '/watchdog-data/switch_rps.json'


def _load_rps_settings() -> dict:
    try:
        with open(_SWITCH_RPS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_rps_settings(data: dict) -> None:
    tmp = _SWITCH_RPS_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.replace(tmp, _SWITCH_RPS_FILE)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@switch_health_bp.route('/switch-health')
@login_required
@permission_required('manage_switch_ports')
def switch_health():
    switch_hosts = get_switch_hosts()
    return render_template('admin_switch_health.html', switch_hosts=switch_hosts)


@switch_health_bp.route('/switch-health/data')
@login_required
@permission_required('manage_switch_ports')
def switch_health_data():
    """AJAX: run hardware health commands on all HP5130 switches and return JSON."""
    from datetime import datetime
    try:
        switch_hosts = get_switch_hosts()
        commands = {
            'power':       ('display power',                  ''),
            'fan':         ('display fan',                    ''),
            'environment': ('display environment',            ''),
            'diagnostic':  ('display diagnostic-information', 'N\n'),
        }

        def _fetch(host, key, cmd, extra):
            out = run_switch_command(host, cmd, extra_input=extra, disable_paging=True)
            return host, key, out.strip() if out else None

        results = {host: {} for host in switch_hosts}
        tasks = [
            (host, key, cmd, extra)
            for host in switch_hosts
            for key, (cmd, extra) in commands.items()
        ]
        with ThreadPoolExecutor(max_workers=len(tasks) or 1) as pool:
            futures = {pool.submit(_fetch, h, k, c, e): None for h, k, c, e in tasks}
            for fut in as_completed(futures):
                h, k, val = fut.result()
                results[h][k] = val

        return jsonify({
            'switches': results,
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        })
    except Exception as exc:
        logger.exception("switch_health_data error")
        return jsonify({'error': str(exc), 'switches': {}, 'timestamp': ''}), 500


@switch_health_bp.route('/switch-health/rps', methods=['GET'])
@login_required
@permission_required('manage_switch_ports')
def rps_get():
    return jsonify(_load_rps_settings())


@switch_health_bp.route('/switch-health/rps', methods=['POST'])
@login_required
@permission_required('manage_switch_ports')
def rps_set():
    from flask import request
    data = request.get_json(silent=True) or {}
    host = (data.get('host') or '').strip()
    rps  = bool(data.get('rps'))
    if not host:
        return jsonify({'ok': False, 'error': 'missing host'}), 400
    settings = _load_rps_settings()
    settings[host] = rps
    try:
        _save_rps_settings(settings)
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500
    return jsonify({'ok': True})
