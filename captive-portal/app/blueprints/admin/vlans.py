"""
Admin — VLAN Configuration (spec section 12 / CODEBASE section 2).

Routes:
  GET/POST /admin/vlan-config              VLAN configuration page
  GET      /api/admin/kea-config           return current dhcp4.json as text
  GET      /api/admin/vlan-push-status     poll background push job status
  POST     /api/admin/push-acl-baseline    trigger ACL baseline push
  GET      /api/admin/switch-current-config  return 'display current-configuration' output from all switches
"""

import json
import logging
import os
import secrets
import threading

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import login_required

from extensions import db
from models import ISPRouter, Setting, VlanMapping
from core.auth import permission_required
from core.network import (
    reset_acl_baseline, reset_acl_queue_files, reset_dns_hijack_rules,
    reset_pi_network_masks, reset_vlan_interface_masks,
)
from core.vlan_utils import (
    FIXED_VLAN_STATUSES, POOL_PREFIX_CHOICES, POOL_PREFIX_STATUSES,
    WIRED_UNREGISTERED_STATUS, get_vlan_entries, get_vlan_map,
    get_vlan_prefix_map, parse_valid_vlan_ids, parse_visible_vlans,
    update_kea_config, restart_kea_container,
)

logger = logging.getLogger(__name__)

vlans_bp = Blueprint('vlans', __name__)


def _pihole_redis():
    """Return a Redis client for job-status sharing across gunicorn workers."""
    try:
        import redis as _redis_module
        url = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
        return _redis_module.from_url(url, decode_responses=True)
    except Exception:
        return None


def _get_vlan_prefix_by_id() -> dict:
    """Return {vlan_id: prefix} for all known VLANs."""
    vlan_map = get_vlan_map()
    prefix_map = get_vlan_prefix_map()
    prefix_by_id = {}
    for status, vlan_id in vlan_map.items():
        if status in prefix_map:
            prefix_by_id[vlan_id] = prefix_map[status]
        else:
            prefix_by_id[vlan_id] = 24
    return prefix_by_id


# ---------------------------------------------------------------------------
# VLAN configuration page
# ---------------------------------------------------------------------------

@vlans_bp.route('/vlan-config', methods=['GET', 'POST'])
@login_required
@permission_required('manage_vlans')
def vlan_config():
    """VLAN configuration page — edit VLAN mappings, pool prefixes, ISP router assignments."""
    if request.method == 'POST':
        valid_vlan_ids = set(parse_valid_vlan_ids())
        statuses          = request.form.getlist('vlan_status')
        names             = request.form.getlist('vlan_name')
        vlan_ids          = request.form.getlist('vlan_id')
        ssids             = request.form.getlist('vlan_ssid')
        wired_statuses    = set(request.form.getlist('vlan_wired'))
        password_statuses = set(request.form.getlist('vlan_require_password'))
        remove_statuses   = set(request.form.getlist('vlan_remove'))
        isp_router_ids    = request.form.getlist('vlan_isp_router')
        visible_vlans_list = request.form.getlist('vlan_visible_vlans')

        warnings = []
        errors = []
        seen_statuses = set()
        seen_vlan_ids = set()
        pbr_changes = []
        visibility_changed = False

        for index, status_raw in enumerate(statuses):
            status = (status_raw or '').strip().lower()
            if not status:
                continue
            if status in seen_statuses:
                warnings.append(f"Duplicate VLAN key skipped: {status}")
                continue
            seen_statuses.add(status)

            if status == WIRED_UNREGISTERED_STATUS:
                continue

            if status in remove_statuses:
                mapping = VlanMapping.query.filter_by(status=status).first()
                if mapping:
                    db.session.delete(mapping)
                continue

            vlan_id_raw = vlan_ids[index] if index < len(vlan_ids) else ''
            try:
                vlan_id = int(vlan_id_raw)
            except (TypeError, ValueError):
                warnings.append(f"Invalid VLAN ID for {status}: {vlan_id_raw}")
                continue

            if valid_vlan_ids and vlan_id not in valid_vlan_ids:
                warnings.append(f"VLAN {vlan_id} not in VALID_VLANS; skipped {status}.")
                continue

            if vlan_id in seen_vlan_ids:
                errors.append(f"Duplicate VLAN ID {vlan_id} used by {status}.")
                continue
            seen_vlan_ids.add(vlan_id)

            display_name = (names[index] if index < len(names) else '').strip()
            if not display_name:
                display_name = status.title()

            ssid = (ssids[index] if index < len(ssids) else '').strip() or None
            wired_enabled    = status in wired_statuses
            require_password = status in password_statuses

            isp_router_id_raw = isp_router_ids[index] if index < len(isp_router_ids) else ''
            new_isp_router_id = (
                int(isp_router_id_raw) if isp_router_id_raw.strip().isdigit() else None
            )

            mapping = VlanMapping.query.filter_by(status=status).first()
            if mapping:
                old_isp_router = mapping.isp_router
                new_isp_router = (
                    ISPRouter.query.get(new_isp_router_id) if new_isp_router_id else None
                )
                if (mapping.isp_router_id or None) != (new_isp_router_id or None):
                    pbr_changes.append((
                        vlan_id,
                        old_isp_router.pbr_name if old_isp_router else None,
                        new_isp_router.pbr_name if new_isp_router else None,
                    ))
                mapping.vlan_id       = vlan_id
                mapping.display_name  = display_name
                mapping.ssid          = ssid
                mapping.wired_enabled = wired_enabled
                mapping.require_password = require_password
                mapping.isp_router_id = new_isp_router_id
                new_vv = parse_visible_vlans(visible_vlans_list, index)
                if (mapping.visible_vlans or '') != new_vv:
                    visibility_changed = True
                mapping.visible_vlans = new_vv or None
            else:
                new_vv = parse_visible_vlans(visible_vlans_list, index)
                if new_vv:
                    visibility_changed = True
                mapping = VlanMapping(
                    status=status,
                    vlan_id=vlan_id,
                    display_name=display_name,
                    ssid=ssid,
                    wired_enabled=wired_enabled,
                    require_password=require_password,
                    isp_router_id=new_isp_router_id,
                    visible_vlans=new_vv or None,
                )
                db.session.add(mapping)

        # Pool prefix settings
        prefix_by_status = {}
        prefix_changed = False
        changed_statuses = []
        for status in POOL_PREFIX_STATUSES:
            previous_raw = Setting.get_value(f'vlan_prefix_{status}', '24')
            try:
                previous_prefix = int(previous_raw)
            except (TypeError, ValueError):
                previous_prefix = 24
            if previous_prefix not in POOL_PREFIX_CHOICES:
                previous_prefix = 24
            raw = request.form.get(f'prefix_{status}', '24')
            try:
                prefix = int(raw)
            except (TypeError, ValueError):
                prefix = 24
            if prefix not in POOL_PREFIX_CHOICES:
                prefix = 24
            if prefix != previous_prefix:
                prefix_changed = True
                changed_statuses.append(status)
            Setting.set_value(f'vlan_prefix_{status}', str(prefix))
            prefix_by_status[status] = prefix

        if errors:
            db.session.rollback()
            for message in errors:
                flash(message, 'error')
            return redirect(url_for('admin.vlans.vlan_config'))

        db.session.commit()

        # Capture data needed by background worker before request context ends
        _pbr_changes        = list(pbr_changes)
        _prefix_changed     = prefix_changed
        _visibility_changed = visibility_changed
        _changed_statuses   = list(changed_statuses)
        _vlan_map           = get_vlan_map()
        _vlan_prefix_by_id  = {}
        _changed_vlan_ids   = []
        for _status, _prefix in prefix_by_status.items():
            _vid = _vlan_map.get(_status)
            if _vid:
                _vlan_prefix_by_id[_vid] = _prefix
                if _status in _changed_statuses:
                    _changed_vlan_ids.append(_vid)

        _push_job_id = secrets.token_hex(16)
        session['vlan_push_job_id'] = _push_job_id

        def _background_vlan_push():
            from app import app as _app
            _errors = []
            rdb = _pihole_redis()
            if rdb:
                try:
                    rdb.set(
                        f'vlan_push_job:{_push_job_id}',
                        json.dumps({'state': 'running'}),
                        ex=300,
                    )
                except Exception:
                    pass

            with _app.app_context():
                try:
                    # 1. Push PBR/NQA so ISP router assignments are current
                    try:
                        from blueprints.admin.isp_routers import push_pbr_nqa_to_switches
                        push_pbr_nqa_to_switches()
                    except Exception as exc:
                        logger.warning("BG VLAN push: PBR/NQA failed: %s", exc)
                        _errors.append(f'PBR/NQA: {exc}')

                    # 2. Assign changed PBR policies to VLAN interfaces
                    if _pbr_changes:
                        from concurrent.futures import ThreadPoolExecutor, as_completed
                        from core.switch import get_switch_hosts, run_switch_command
                        switch_hosts = get_switch_hosts()
                        pbr_tasks = []
                        for (pbr_vlan_id, old_pbr, new_pbr) in _pbr_changes:
                            for host in switch_hosts:
                                if new_pbr:
                                    cmd = (
                                        f"system-view\n"
                                        f"interface Vlan-interface{pbr_vlan_id}\n"
                                        f" undo ip policy-based-route\n"
                                        f" ip policy-based-route {new_pbr}\n"
                                        f"quit\nquit\nsave force"
                                    )
                                elif old_pbr:
                                    cmd = (
                                        f"system-view\n"
                                        f"interface Vlan-interface{pbr_vlan_id}\n"
                                        f" undo ip policy-based-route {old_pbr}\n"
                                        f"quit\nquit\nsave force"
                                    )
                                else:
                                    continue
                                pbr_tasks.append((host, cmd))
                        if pbr_tasks:
                            with ThreadPoolExecutor(max_workers=len(pbr_tasks)) as ex:
                                for f in as_completed(
                                    [ex.submit(run_switch_command, h, c) for h, c in pbr_tasks]
                                ):
                                    try:
                                        f.result()
                                    except Exception as exc:
                                        logger.warning("BG PBR assign SSH error: %s", exc)
                                        _errors.append(str(exc))

                    # 3. Write new Kea config
                    try:
                        update_kea_config(_vlan_prefix_by_id)
                    except Exception as exc:
                        logger.warning("BG Kea config write failed: %s", exc)
                        _errors.append(f'Kea config: {exc}')

                    # 4. ACL baseline + interface masks if prefix or visibility changed
                    if _prefix_changed or _visibility_changed:
                        ok = reset_acl_baseline()
                        if not ok:
                            _errors.append('ACL baseline push failed')
                    if _prefix_changed:
                        reset_vlan_interface_masks(_changed_vlan_ids)
                        reset_pi_network_masks(_changed_vlan_ids)

                    # 5. Restart Kea
                    try:
                        restart_kea_container()
                    except Exception as exc:
                        logger.warning("BG Kea restart failed: %s", exc)
                        _errors.append(f'Kea restart: {exc}')

                except Exception as exc:
                    logger.error("BG VLAN push raised: %s", exc)
                    _errors.append(str(exc))

                if rdb:
                    try:
                        rdb.set(
                            f'vlan_push_job:{_push_job_id}',
                            json.dumps({
                                'state': 'done',
                                'ok': not _errors,
                                'errors': _errors,
                            }),
                            ex=120,
                        )
                    except Exception:
                        pass

        threading.Thread(target=_background_vlan_push, daemon=True).start()

        flash(
            'VLAN configuration saved. Switch and Kea updates are being applied in the background.',
            'success',
        )
        for message in warnings:
            flash(message, 'warning')
        logger.info("Admin updated VLAN configuration (background push started)")
        return redirect(url_for('admin.vlans.vlan_config'))

    # GET
    vlan_map     = get_vlan_map()
    prefix_map   = get_vlan_prefix_map()
    vlan_entries = [e for e in get_vlan_entries() if e.status != WIRED_UNREGISTERED_STATUS]
    valid_vlan_ids = parse_valid_vlan_ids()
    isp_routers  = ISPRouter.query.order_by(ISPRouter.id).all()

    kea_config_json = None
    kea_config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
    try:
        with open(kea_config_path, 'r', encoding='utf-8') as _f:
            kea_config_json = _f.read()
    except OSError:
        pass

    return render_template(
        'admin_vlan_config.html',
        vlan_map=vlan_map,
        vlan_entries=vlan_entries,
        valid_vlan_ids=valid_vlan_ids,
        fixed_statuses=FIXED_VLAN_STATUSES,
        prefix_map=prefix_map,
        prefix_choices=POOL_PREFIX_CHOICES,
        prefix_statuses=POOL_PREFIX_STATUSES,
        isp_routers=isp_routers,
        kea_config_json=kea_config_json,
        vlan_push_job_id=session.get('vlan_push_job_id'),
    )


# ---------------------------------------------------------------------------
# Kea config API
# ---------------------------------------------------------------------------

@vlans_bp.route('/api/admin/kea-config')
@login_required
@permission_required('manage_vlans')
def kea_config_api():
    """Return the current Kea dhcp4.json content as plain text."""
    kea_config_path = os.getenv('KEA_CONFIG_PATH', '/kea/config/dhcp4.json')
    try:
        with open(kea_config_path, 'r', encoding='utf-8') as _f:
            return _f.read(), 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except OSError:
        return '', 404, {'Content-Type': 'text/plain'}


# ---------------------------------------------------------------------------
# VLAN push status polling
# ---------------------------------------------------------------------------

@vlans_bp.route('/api/admin/vlan-push-status')
@login_required
def vlan_push_status():
    """Return the status of the most recent background VLAN push job."""
    job_id = session.get('vlan_push_job_id')
    if not job_id:
        return jsonify({'state': 'none'})
    rdb = _pihole_redis()
    if not rdb:
        return jsonify({'state': 'error'})
    try:
        raw = rdb.get(f'vlan_push_job:{job_id}')
        if not raw:
            session.pop('vlan_push_job_id', None)
            return jsonify({'state': 'expired'})
        data = json.loads(raw)
        if data.get('state') == 'done':
            session.pop('vlan_push_job_id', None)
        return jsonify(data)
    except Exception:
        return jsonify({'state': 'error'})


# ---------------------------------------------------------------------------
# Push ACL baseline
# ---------------------------------------------------------------------------

@vlans_bp.route('/api/admin/push-acl-baseline', methods=['POST'])
@login_required
@permission_required('manage_vlans')
def push_acl_baseline():
    """Trigger a full ACL baseline + inter-VLAN isolation push in the background."""
    job_id = secrets.token_hex(16)
    session['vlan_push_job_id'] = job_id

    def _run():
        from app import app as _app
        errors = []
        rdb = _pihole_redis()
        if rdb:
            try:
                rdb.set(f'vlan_push_job:{job_id}', json.dumps({'state': 'running'}), ex=300)
            except Exception:
                pass
        try:
            with _app.app_context():
                ok = reset_acl_baseline()
                if not ok:
                    errors.append('ACL baseline push failed — check server logs')
        except Exception as exc:
            logger.exception('push_acl_baseline thread crashed: %s', exc)
            errors.append(f'Unexpected error: {exc}')
        finally:
            if rdb:
                try:
                    rdb.set(
                        f'vlan_push_job:{job_id}',
                        json.dumps({'state': 'done', 'ok': not errors, 'errors': errors}),
                        ex=300,
                    )
                except Exception:
                    pass

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})


# ---------------------------------------------------------------------------
# Switch current configuration API
# ---------------------------------------------------------------------------

@vlans_bp.route('/api/admin/switch-current-config')
@login_required
@permission_required('manage_vlans')
def switch_current_config():
    """Return the output of 'display current-configuration' from all configured HP5130 switches."""
    from core.switch import get_switch_hosts, run_switch_command

    hosts = get_switch_hosts()
    results = {}
    for host in hosts:
        output = run_switch_command(host, 'display current-configuration', disable_paging=True)
        results[host] = output if output is not None else '# Failed to retrieve configuration from this switch.'
    return jsonify(results)