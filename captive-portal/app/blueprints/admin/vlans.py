"""
Admin — VLAN Configuration (spec section 12 / CODEBASE section 2).

Routes:
  GET/POST /admin/vlan-config              VLAN configuration page
  GET      /api/admin/kea-config           return current dhcp4.json as text
  GET      /api/admin/vlan-push-status     poll background push job status
  POST     /api/admin/push-acl-baseline    trigger ACL baseline push
  GET      /api/admin/switch-current-config  return 'display current-configuration' output from all switches
"""

import ipaddress
import json
import logging
import os
import secrets
import threading

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import login_required

from extensions import db
from core.switch import get_switch_hosts
from models import ISPRouter, Setting, VlanMapping
from core.auth import permission_required
from core.network import (
    reset_acl_baseline, reset_acl_queue_files, reset_dns_hijack_rules,
    reset_pi_network_masks, 
)
from core.vlan_utils import (
    FIXED_VLAN_STATUSES, POOL_PREFIX_CHOICES, POOL_PREFIX_STATUSES,
    WIRED_UNREGISTERED_STATUS, get_management_vlan_id, get_vlan_entries, get_vlan_map,
    get_vlan_prefix_map, parse_valid_vlan_ids, parse_visible_vlans,
    update_kea_config, restart_kea_container,
)
from core.hp5130_policy import write_hp5130_policy_file

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


def _parse_external_vlan_subnets() -> list:
    """
    Parse EXTERNAL_VLAN_SUBNETS env: '40:192.168.40.0/24,50:10.20.0.0/23'
    Returns list of (vlan_id, IPv4Network).
    """
    raw = os.getenv('EXTERNAL_VLAN_SUBNETS', '') or ''
    out = []
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry or ':' not in entry:
            continue
        vlan_str, cidr = entry.split(':', 1)
        try:
            vlan_id = int(vlan_str.strip())
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except (ValueError, TypeError):
            continue
        out.append((vlan_id, net))
    return out


def _collect_internal_networks(prefix_by_status: dict) -> list:
    """
    Build IPv4Network list for Kea-managed pools:
    NETWORK_WORD.{vlan_id}.0/{prefix}
    """
    network_word = os.getenv('NETWORK_WORD', '192.168')
    vlan_map = get_vlan_map()
    nets = []
    for status, vlan_id in vlan_map.items():
        prefix = int(prefix_by_status.get(status, 24) or 24)
        if prefix not in (24, 23, 22, 21):
            prefix = 24
        try:
            nets.append(
                ipaddress.ip_network(f'{network_word}.{int(vlan_id)}.0/{prefix}', strict=False)
            )
        except ValueError:
            continue
    # Management / wired defaults if present in env
    for env_key, default_vid in (('MANAGEMENT_VLAN', 99), ('WIRED_VLAN', 250)):
        try:
            vid = int(os.getenv(env_key, str(default_vid)))
        except ValueError:
            continue
        try:
            nets.append(ipaddress.ip_network(f'{network_word}.{vid}.0/24', strict=False))
        except ValueError:
            continue
    return nets


def _find_subnet_overlaps(networks: list) -> list:
    """Return list of (net_a, net_b) pairs that overlap (skip identical duplicates)."""
    overlaps = []
    for i, a in enumerate(networks):
        for b in networks[i + 1:]:
            if a == b:
                continue
            if a.overlaps(b):
                overlaps.append((str(a), str(b)))
    return overlaps


def _proposed_networks_for_overlap_check(prefix_by_status: dict) -> list:
    """
    Collect every subnet that must not overlap after a VLAN / prefix save:
      - Kea-managed internal pools (NETWORK_WORD.{vlan}.0/{prefix})
      - management + wired /24
      - external upstream-DHCP subnets from EXTERNAL_VLAN_SUBNETS
      - ISP router subnets from the DB (when available)
    """
    nets = list(_collect_internal_networks(prefix_by_status))
    for _vid, ext_net in _parse_external_vlan_subnets():
        nets.append(ext_net)
    try:
        for router in ISPRouter.query.all():
            subnet = getattr(router, 'subnet', None)
            if not subnet:
                continue
            try:
                nets.append(ipaddress.ip_network(str(subnet).strip(), strict=False))
            except ValueError:
                continue
    except Exception:
        pass
    return nets


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
        allow_doh_statuses = set(request.form.getlist('vlan_allow_doh'))
        warnings = []
        errors = []
        seen_statuses = set()
        seen_vlan_ids = set()
        pbr_changes = []
        visibility_changed = False
        doh_changed = False

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
                allow_doh = status in allow_doh_statuses
                if bool(getattr(mapping, "allow_doh", False)) != allow_doh:
                    doh_changed = True
                mapping.allow_doh = allow_doh
            else:
                new_vv = parse_visible_vlans(visible_vlans_list, index)
                if new_vv:
                    visibility_changed = True
                allow_doh = status in allow_doh_statuses
                if allow_doh:
                    doh_changed = True
                mapping = VlanMapping(
                    status=status,
                    vlan_id=vlan_id,
                    display_name=display_name,
                    ssid=ssid,
                    wired_enabled=wired_enabled,
                    require_password=require_password,
                    isp_router_id=new_isp_router_id,
                    visible_vlans=new_vv or None,
                    allow_doh=allow_doh,
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

        # Reject saves that would make any managed subnet overlap another
        # (internal pools vs each other, vs external upstream-DHCP VLANs, vs ISP subnets).
        try:
            for net_a, net_b in _find_subnet_overlaps(
                _proposed_networks_for_overlap_check(prefix_by_status)
            ):
                errors.append(f'Subnet overlap: {net_a} overlaps {net_b}')
        except Exception as exc:
            logger.exception('Subnet overlap check failed')
            errors.append(f'Subnet overlap check failed: {exc}')

        if errors:
            db.session.rollback()
            for message in errors:
                flash(message, 'error')
            return redirect(url_for('admin.vlans.vlan_config'))

        db.session.commit()


        _hp5130_policy_error = None
        try:
            _hp5130_policy_path = write_hp5130_policy_file()
            logger.info("HP5130 policy JSON updated: %s", _hp5130_policy_path)
        except Exception as exc:
            _hp5130_policy_error = str(exc)
            logger.exception("Failed to update HP5130 policy JSON after VLAN save")
            flash(
                f'VLAN configuration saved, but HP5130 policy JSON could not be written: {exc}',
                'warning',
            )

        # Capture data needed by background worker before request context ends
        _pbr_changes        = list(pbr_changes)
        _prefix_changed     = prefix_changed
        _visibility_changed = visibility_changed
        _doh_changed        = doh_changed
        _changed_statuses   = list(changed_statuses)
        _hp5130_policy_write_error = _hp5130_policy_error
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
            from core.vlan_utils import sync_mdns_reflector
            from subprocess import run
            _errors = []
            rdb = _pihole_redis()

            try:
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
                        if _hp5130_policy_write_error:
                            _errors.append(f'HP5130 policy JSON: {_hp5130_policy_write_error}')

                        # Run full ACL + PBR + NQA baseline when anything relevant changed
                        if _pbr_changes or _prefix_changed or _visibility_changed or _doh_changed:
                            ok = reset_acl_baseline()
                            if not ok:
                                _errors.append('ACL/PBR/NQA baseline push failed')
                        if _visibility_changed or _prefix_changed:
                            try:
                                sync_mdns_reflector()
                            except Exception as exc:
                                logger.exception("Failed to sync mDNS reflector: %s", exc)
                                _errors.append(f'mDNS reflector sync failed: {exc}')
                            try:
                                from blueprints.admin.switch_ports import refresh_pi_trunk_vlans
                                refresh_pi_trunk_vlans()
                            except Exception as exc:
                                logger.exception("Failed to refresh Pi trunk VLANs: %s", exc)
                                _errors.append(f'Pi trunk VLAN refresh failed: {exc}')

                        # 2. Re-apply per-device blocks AFTER the baseline
                        #    (this is critical — baseline would have wiped them)
                        try:
                            from core.network import reapply_all_ip_blocks
                            pushed, failed = reapply_all_ip_blocks()
                            if failed > 0:
                                logger.warning("Re-applied IP blocks after baseline: %d pushed, %d failed", pushed, failed)
                                _errors.append(f'IP block re-apply had {failed} failures')
                        except Exception as exc:
                            logger.exception("Failed to re-apply IP blocks in background: %s", exc)
                            _errors.append(f'IP block re-apply failed: {exc}')                    

                        # Write new Kea config
                        try:
                            update_kea_config(_vlan_prefix_by_id)
                        except Exception as exc:
                            logger.warning("BG Kea config write failed: %s", exc)
                            _errors.append(f'Kea config: {exc}')

                        # Interface masks (only needed on prefix change)
                        if _prefix_changed:
                            reset_pi_network_masks(_changed_vlan_ids)
                            try:
                                script_path = os.getenv('DNS_SCRIPT', '/scripts/dns-hijack.sh')
                                if os.path.isfile(script_path):
                                    result = subprocess.run(
                                        [script_path, "refresh-blocked-pools"],
                                        capture_output=True, text=True, timeout=30
                                    )

                                    if result.returncode == 0:
                                        if result.stdout.strip():
                                            logger.info("DNS hijack refresh output:\n%s", result.stdout.strip())
                                        logger.info("Blocked-pool DNS hijack rules refreshed after prefix change")
                                    else:
                                        logger.warning(
                                            "Failed to refresh blocked-pool DNS hijack (exit=%s)\nSTDOUT:\n%s\nSTDERR:\n%s",
                                            result.returncode,
                                            result.stdout.strip() or '<empty>',
                                            result.stderr.strip() or '<empty>'
                                        )
                                else:
                                    logger.warning("DNS hijack script not found: %s", script_path)
                            except Exception as exc:
                                logger.warning("Error refreshing blocked-pool DNS hijack: %s", exc)

                        # Restart Kea
                        try:
                            restart_kea_container()
                        except Exception as exc:
                            logger.warning("BG Kea restart failed: %s", exc)
                            _errors.append(f'Kea restart: {exc}')

                    except Exception as exc:
                        logger.error("BG VLAN push raised: %s", exc)
                        _errors.append(str(exc))

            except Exception as exc:
                logger.error("BG VLAN push raised: %s", exc)
                _errors.append(str(exc))

            finally:
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
    mgmt_vlan_id = get_management_vlan_id()
    vlan_entries = [
        e for e in get_vlan_entries()
        if e.status != WIRED_UNREGISTERED_STATUS and e.vlan_id != mgmt_vlan_id
    ]
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
        switch_hosts=get_switch_hosts(),
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