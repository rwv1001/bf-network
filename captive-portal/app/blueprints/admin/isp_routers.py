"""
Admin — ISP Router Management (spec section 12 / CODEBASE section 7).

Routes:
  GET/POST /admin/isp-routers                          ISP router management page
  POST     /admin/push-pbr-nqa                         push PBR/NQA to all switches
  POST     /admin/push-vlan-interfaces                 push VLAN interface config
  POST     /admin/reapply-acl-blocks                   reapply ACL baseline + IP blocks
  POST     /admin/push-all-switch-config               start background full push
  GET      /admin/push-all-switch-config/status/<id>   poll job status
"""

import ipaddress
import json
import logging
import os
import threading

from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import text

from extensions import db
from models import ISPRouter, VlanMapping, Setting
from core.auth import permission_required
from core.network import reset_acl_baseline, reapply_all_ip_blocks, reset_vlan_interface_masks
from core.switch import (
    COMMON_PORT_UNDO_COMMANDS,
    expand_switch_iface_name, get_switch_hosts, get_switch_host_for_isp_router,
    run_switch_command, switch_host_for_port,
)

logger = logging.getLogger(__name__)

isp_routers_bp = Blueprint('isp_routers', __name__)


def _net_word() -> str:
    return os.getenv('NETWORK_WORD', '192.168')


# ---------------------------------------------------------------------------
# Push-job helpers (shared temp-file approach for multi-worker gunicorn)
# ---------------------------------------------------------------------------

def _push_job_path(job_id: str):
    import re as _re
    if not _re.fullmatch(r'[0-9a-f]{32}', job_id):
        return None
    return f'/tmp/push-all-{job_id}.json'


def _push_job_write(job_id: str, data: dict) -> None:
    path = _push_job_path(job_id)
    if path:
        try:
            with open(path, 'w') as fh:
                json.dump(data, fh)
        except Exception:
            pass


def _push_job_read(job_id: str):
    path = _push_job_path(job_id)
    if not path:
        return None
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Switch config builders
# ---------------------------------------------------------------------------

def _build_isp_router_switch_config(router: ISPRouter, switch_host: str) -> str:
    last_octet = switch_host.split('.')[-1]
    host_ip    = f"{_net_word()}.{router.vlan_id}.{last_octet}"
    pbr_name   = router.pbr_name
    nqa_name   = pbr_name.lower().replace('-', '').replace(' ', '_')
    track_id   = router.id
    name_upper = router.name.upper().replace(' ', '_')

    assigned_vlans = [
        m.vlan_id for m in
        VlanMapping.query.filter_by(isp_router_id=router.id).all()
    ]

    lines = [
        'system-view',
        f'vlan {router.vlan_id}',
        f' description UPLINK-TO-{name_upper}',
        'quit',
        f'dhcp snooping enable vlan {router.vlan_id}',
        f'vlan {router.vlan_id}',
        ' dhcp snooping binding record',
        'quit',
        f'interface Vlan-interface{router.vlan_id}',
        f' description UPLINK-TO-{name_upper}',
        f' ip address {host_ip} 255.255.255.0',
        'quit',
        'acl advanced 3001',
        ' description PBR-local-traffic-normal-routing',
        f' rule 10 permit ip destination {_net_word()}.0.0 0.0.255.255',
        'quit',
        *[cmd for vlan_id in assigned_vlans for cmd in (
            f'interface Vlan-interface{vlan_id}',
            ' undo ip policy-based-route',
            'quit',
        )],
        f'undo policy-based-route {pbr_name}',
        f'undo track {track_id}',
        f'undo nqa schedule admin {nqa_name}',
        f'undo nqa entry admin {nqa_name}',
        f'nqa entry admin {nqa_name}',
        ' type icmp-echo',
        f' destination ip {router.gateway_ip}',
        ' frequency 5',
        ' reaction 1 checked-element probe-fail threshold-type consecutive 3 action-type trigger-only',
        'quit',
        f'nqa schedule admin {nqa_name} start-time now lifetime forever',
        f'track {track_id} nqa entry admin {nqa_name} reaction 1',
        f'policy-based-route {pbr_name} deny node 5',
        ' if-match acl 3001',
        'quit',
        f'policy-based-route {pbr_name} permit node 10',
        f' apply next-hop {router.gateway_ip} track {track_id}',
        'quit',
        *[cmd for vlan_id in assigned_vlans for cmd in (
            f'interface Vlan-interface{vlan_id}',
            f' ip policy-based-route {pbr_name}',
            'quit',
        )],
        'quit',
        'save force',
    ]
    return '\n'.join(lines)


def _build_isp_router_port_config(port_name: str, router: ISPRouter) -> str:
    expanded   = expand_switch_iface_name(port_name)
    name_upper = router.name.upper().replace(' ', '_')

    lines = [
        'system-view',
        f'interface {expanded}',
    ] + COMMON_PORT_UNDO_COMMANDS + [
        f'interface {expanded}',
        f' description TRUNK-TO-{name_upper}',
        ' port link-type trunk',
        ' port trunk permit vlan 1',
        f' port trunk permit vlan {router.vlan_id}',
        ' dhcp snooping trust',
        ' arp detection trust',
        'quit',
        'quit',
        'save force',
    ]
    return '\n'.join(lines)


def _build_isp_router_block_acl(acl_number: int, router: ISPRouter,
                                  excluded_subnets: list) -> str:
    lines = ['system-view', f'acl advanced {acl_number}']
    for rule_num in range(50, 100):
        lines.append(f' undo rule {rule_num}')
    for i, (network, wildcard) in enumerate(excluded_subnets):
        lines.append(f' rule {50 + i} deny ip source {network} {wildcard}')
    lines.extend(['quit', 'quit', 'save force'])
    return '\n'.join(lines)


def _build_remove_isp_router_full(router: ISPRouter) -> str:
    return '\n'.join([
        'system-view',
        f'undo policy-based-route {router.pbr_name}',
        f'undo interface Vlan-interface{router.vlan_id}',
        f'undo vlan {router.vlan_id}',
        f'undo dhcp snooping enable vlan {router.vlan_id}',
        'quit',
        'save force',
    ])


def _build_remove_isp_router_vlan(vlan_id: int) -> str:
    return '\n'.join([
        'system-view',
        f'undo interface Vlan-interface{vlan_id}',
        f'undo vlan {vlan_id}',
        f'undo dhcp snooping enable vlan {vlan_id}',
        'quit',
        'save force',
    ])


def _build_remove_isp_router_pbr(pbr_name: str) -> str:
    return '\n'.join([
        'system-view',
        f'undo policy-based-route {pbr_name}',
        'quit',
        'save force',
    ])


def _build_pbr_undo_next_hop(pbr_name: str, old_gateway_ip: str) -> str:
    return '\n'.join([
        'system-view',
        f'policy-based-route {pbr_name} permit node 10',
        f' undo apply next-hop {old_gateway_ip}',
        'quit',
        'quit',
        'save force',
    ])


def _build_vlan_pbr_assign(vlan_id: int, pbr_name: str) -> str:
    return '\n'.join([
        'system-view',
        f'interface Vlan-interface{vlan_id}',
        ' undo ip policy-based-route',
        f' ip policy-based-route {pbr_name}',
        'quit',
        'quit',
        'save force',
    ])


def _build_vlan_pbr_remove(vlan_id: int, pbr_name: str) -> str:
    return '\n'.join([
        'system-view',
        f'interface Vlan-interface{vlan_id}',
        f' undo ip policy-based-route {pbr_name}',
        'quit',
        'quit',
        'save force',
    ])


def _build_reset_port_config(port_name: str) -> str:
    expanded = expand_switch_iface_name(port_name)
    return '\n'.join([
        'system-view',
        f'interface {expanded}',
        ] + COMMON_PORT_UNDO_COMMANDS + [
        'quit',
        'quit',
        'save force',
    ])


def _build_isl_trunk_add_vlan(isl_port: str, vlan_id: int) -> str:
    return '\n'.join([
        'system-view',
        f'interface {isl_port}',
        f' port trunk permit vlan {vlan_id}',
        'quit',
        'quit',
        'save force',
    ])


def _build_isl_trunk_remove_vlan(isl_port: str, vlan_id: int) -> str:
    return '\n'.join([
        'system-view',
        f'interface {isl_port}',
        f' undo port trunk permit vlan {vlan_id}',
        'quit',
        'quit',
        'save force',
    ])


# ---------------------------------------------------------------------------
# Internal action helpers
# ---------------------------------------------------------------------------

def _apply_isp_router_to_switches(router: ISPRouter) -> None:
    switch_hosts = get_switch_hosts()
    failed = []
    for host in switch_hosts:
        cfg = _build_isp_router_switch_config(router, host)
        if run_switch_command(host, cfg) is None:
            failed.append(host)
    if failed:
        flash(f'Switch config push failed for: {", ".join(failed)}', 'warning')


def _remove_isp_router_from_switches(router: ISPRouter) -> None:
    for host in get_switch_hosts():
        run_switch_command(host, _build_remove_isp_router_full(router))


def _remove_isp_router_vlan_from_switches(old_vlan_id: int) -> None:
    for host in get_switch_hosts():
        run_switch_command(host, _build_remove_isp_router_vlan(old_vlan_id))


def _remove_isp_router_pbr_from_switches(pbr_name: str) -> None:
    for host in get_switch_hosts():
        run_switch_command(host, _build_remove_isp_router_pbr(pbr_name))


def _set_isp_router_port(port_name: str, router: ISPRouter) -> None:
    host = get_switch_host_for_isp_router(router)
    if not host:
        return
    db.session.execute(text("""
        UPDATE switch_ports
        SET port_role = 'uplink_udm', last_updated = NOW()
        WHERE switch_host = :host AND port_name = :port
    """), {'host': host, 'port': port_name})
    run_switch_command(host, _build_isp_router_port_config(port_name, router))
    db.session.commit()


def _clear_isp_router_port(port_name: str, switch_host: str = None) -> None:
    if not switch_host:
        hosts = get_switch_hosts()
        switch_host = hosts[0] if hosts else ''
    if not switch_host:
        return
    db.session.execute(text("""
        UPDATE switch_ports
        SET port_role = 'unknown', last_updated = NOW()
        WHERE switch_host = :host AND port_name = :port
          AND port_role = 'uplink_udm'
    """), {'host': switch_host, 'port': port_name})
    run_switch_command(switch_host, _build_reset_port_config(port_name))
    db.session.commit()


def _update_isl_trunk_vlan(vlan_id: int, add: bool = True) -> None:
    rows = db.session.execute(text("""
        SELECT switch_host, port_name
        FROM switch_ports
        WHERE port_role = 'inter_switch'
    """)).fetchall()
    for switch_host, port_name in rows:
        expanded = expand_switch_iface_name(port_name)
        cfg = (_build_isl_trunk_add_vlan(expanded, vlan_id)
               if add else _build_isl_trunk_remove_vlan(expanded, vlan_id))
        run_switch_command(switch_host, cfg)


def _get_isp_router_locked_ports() -> dict:
    return {r.switch_port: r.name
            for r in ISPRouter.query.filter(ISPRouter.switch_port.isnot(None)).all()}


def push_pbr_nqa_to_switches() -> bool:
    """
    Push full ISP router PBR + NQA tracking config for all routers to all switches.
    Also applies egress block ACLs on each ISP uplink SVI.
    Returns True if all switches succeeded.
    """
    switch_hosts = get_switch_hosts()
    if not switch_hosts:
        logger.warning("push_pbr_nqa_to_switches: no SWITCH_HOSTS configured")
        return True

    routers = ISPRouter.query.all()
    if not routers:
        return True

    # Build router_id → [(network_addr, wildcard), ...] for all assigned VLANs
    router_subnets = {}
    for vlan in VlanMapping.query.filter(VlanMapping.isp_router_id.isnot(None)).all():
        prefix_raw = Setting.get_value(f'vlan_prefix_{vlan.status}', '24')
        try:
            prefix = int(prefix_raw)
        except (TypeError, ValueError):
            prefix = 24
        try:
            net = ipaddress.IPv4Network(
                f'{_net_word()}.{vlan.vlan_id}.0/{prefix}', strict=False)
            network_addr = str(net.network_address)
            wildcard     = str(ipaddress.IPv4Address(int(net.hostmask)))
        except ValueError:
            continue
        router_subnets.setdefault(vlan.isp_router_id, []).append((network_addr, wildcard))

    tasks = []
    for router in routers:
        for host in switch_hosts:
            cfg = _build_isp_router_switch_config(router, host)
            tasks.append((f'{host}/{router.pbr_name}', host, cfg))

        excluded = []
        for other_router in routers:
            if other_router.id != router.id:
                excluded.extend(router_subnets.get(other_router.id, []))
        acl_number = 3950 + router.id
        block_cfg  = _build_isp_router_block_acl(acl_number, router, excluded)
        for host in switch_hosts:
            tasks.append((f'{host}/{router.pbr_name}/block-acl', host, block_cfg))

    failed = []
    with ThreadPoolExecutor(max_workers=len(tasks) or 1) as executor:
        future_to_label = {
            executor.submit(run_switch_command, host, cfg): label
            for label, host, cfg in tasks
        }
        for future in as_completed(future_to_label):
            label = future_to_label[future]
            try:
                result = future.result()
            except Exception as exc:
                result = None
                logger.warning("push_pbr_nqa_to_switches: exception for %s: %s", label, exc)
            if result is None:
                failed.append(label)

    return len(failed) == 0


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@isp_routers_bp.route('/isp-routers', methods=['GET', 'POST'])
@login_required
@permission_required('manage_isp_routers')
def admin_isp_routers():
    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'add':
            name          = request.form.get('name', '').strip()
            vlan_id_raw   = request.form.get('vlan_id', '').strip()
            switch_port   = request.form.get('switch_port', '').strip() or None
            switch_host_f = switch_host_for_port(switch_port) if switch_port else ''
            if not name or not vlan_id_raw:
                flash('Name and VLAN ID are required.', 'error')
                return redirect(url_for('admin.isp_routers.admin_isp_routers'))
            try:
                vlan_id = int(vlan_id_raw)
            except ValueError:
                flash('VLAN ID must be an integer.', 'error')
                return redirect(url_for('admin.isp_routers.admin_isp_routers'))
            subnet = f'{_net_word()}.{vlan_id}.0/24'
            if ISPRouter.query.filter_by(name=name).first():
                flash(f'A router named "{name}" already exists.', 'error')
                return redirect(url_for('admin.isp_routers.admin_isp_routers'))
            nat_logger_type = request.form.get('nat_logger_type', 'none').strip()
            if nat_logger_type not in ('none', 'udm', 'openwrt'):
                nat_logger_type = 'none'
            router = ISPRouter(
                name=name, subnet=subnet, vlan_id=vlan_id,
                switch_port=switch_port, switch_host=switch_host_f,
                dhcp_snooping_trust=True, nat_logger_type=nat_logger_type,
            )
            db.session.add(router)
            db.session.commit()
            _apply_isp_router_to_switches(router)
            _update_isl_trunk_vlan(router.vlan_id, add=True)
            if switch_port:
                _set_isp_router_port(switch_port, router)
            reset_acl_baseline()
            reapply_all_ip_blocks()
            flash(
                f'ISP router "{name}" added. '
                f'⚠ Set the router LAN IP to {router.gateway_ip} and add a '
                f'static route: Target {_net_word()}.0.0 / Mask 255.255.0.0 / '
                f'Gateway {_net_word()}.{vlan_id}.2 on the router.',
                'success',
            )
            return redirect(url_for('admin.isp_routers.admin_isp_routers'))

        elif action == 'update':
            router = ISPRouter.query.get_or_404(request.form.get('router_id'))
            old_port        = router.switch_port
            old_switch_host = router.switch_host
            old_vlan_id     = router.vlan_id
            old_pbr_name    = router.pbr_name
            router.name = request.form.get('name', router.name).strip()
            if router.vlan_id != 1:
                try:
                    new_vlan_id = int(request.form.get('vlan_id', router.vlan_id))
                    if 2 <= new_vlan_id <= 7:
                        router.vlan_id = new_vlan_id
                except (ValueError, TypeError):
                    pass
            router.subnet      = f'{_net_word()}.{router.vlan_id}.0/24'
            new_port           = request.form.get('switch_port', '').strip() or None
            router.switch_port = new_port
            router.switch_host = switch_host_for_port(new_port) if new_port else ''
            router.dhcp_snooping_trust = True
            new_nat = request.form.get('nat_logger_type', router.nat_logger_type).strip()
            if new_nat in ('none', 'udm', 'openwrt'):
                router.nat_logger_type = new_nat
            db.session.commit()

            if old_pbr_name != router.pbr_name:
                _remove_isp_router_pbr_from_switches(old_pbr_name)

            vlan_changed = old_vlan_id != router.vlan_id
            if vlan_changed:
                old_gateway_ip = f'{_net_word()}.{old_vlan_id}.1'
                for host in get_switch_hosts():
                    run_switch_command(host, _build_pbr_undo_next_hop(router.pbr_name, old_gateway_ip))
                _remove_isp_router_vlan_from_switches(old_vlan_id)

            if old_port and old_port != new_port:
                _clear_isp_router_port(old_port, old_switch_host)

            _apply_isp_router_to_switches(router)

            if new_port and new_port != old_port:
                _set_isp_router_port(new_port, router)
            elif new_port and new_port == old_port:
                if vlan_changed:
                    for host in get_switch_hosts():
                        run_switch_command(host, _build_reset_port_config(new_port))
                _set_isp_router_port(new_port, router)

            if vlan_changed:
                _update_isl_trunk_vlan(old_vlan_id, add=False)
            _update_isl_trunk_vlan(router.vlan_id, add=True)

            baseline_ok = reset_acl_baseline()
            pushed, blk_failed = reapply_all_ip_blocks()
            msg = f'ISP router "{router.name}" updated.'
            if baseline_ok and blk_failed == 0:
                msg += f' ACL baseline pushed and {pushed} block(s) re-applied.'
                flash(msg, 'success')
            else:
                msg += f' ACL baseline or block reapply had errors — check logs.'
                flash(msg, 'warning')
            return redirect(url_for('admin.isp_routers.admin_isp_routers'))

        elif action == 'delete':
            router = ISPRouter.query.get_or_404(request.form.get('router_id'))
            vlan_to_remove = router.vlan_id
            if router.switch_port:
                _clear_isp_router_port(router.switch_port, router.switch_host)
            _remove_isp_router_from_switches(router)
            _update_isl_trunk_vlan(vlan_to_remove, add=False)
            db.session.delete(router)
            db.session.commit()
            flash(f'ISP router "{router.name}" deleted.', 'success')
            return redirect(url_for('admin.isp_routers.admin_isp_routers'))

    routers = ISPRouter.query.order_by(ISPRouter.id).all()
    used_vlan_ids = {r.vlan_id for r in routers}
    switch_hosts  = get_switch_hosts()

    switch_ports_by_host = []
    for host in switch_hosts:
        rows = db.session.execute(
            text("""
                SELECT switch_host, port_name FROM switch_ports
                WHERE switch_host = :host
                ORDER BY
                    (CASE WHEN port_name LIKE 'XGE%' THEN 1 ELSE 0 END),
                    split_part(port_name, '/', 1),
                    CAST(NULLIF(split_part(port_name, '/', 2), '') AS INTEGER),
                    CAST(NULLIF(split_part(port_name, '/', 3), '') AS INTEGER)
            """),
            {'host': host},
        ).fetchall()
        for r in rows:
            switch_ports_by_host.append((r[0], r[1]))

    primary_host      = switch_hosts[0] if switch_hosts else ''
    switch_ports_list = [p for h, p in switch_ports_by_host if h == primary_host]

    return render_template(
        'admin_isp_routers.html',
        routers=routers,
        switch_ports=switch_ports_list,
        switch_ports_by_host=switch_ports_by_host,
        switch_hosts=switch_hosts,
        used_vlan_ids=used_vlan_ids,
        network_word=_net_word(),
    )


@isp_routers_bp.route('/push-pbr-nqa', methods=['POST'])
@login_required
@permission_required('manage_isp_routers')
def push_pbr_nqa():
    ok = push_pbr_nqa_to_switches()
    if ok:
        flash('PBR/NQA config pushed to all switches successfully.', 'success')
    else:
        flash('PBR/NQA push failed for one or more switches — check logs.', 'warning')
    return redirect(url_for('admin.isp_routers.admin_isp_routers'))


@isp_routers_bp.route('/push-vlan-interfaces', methods=['POST'])
@login_required
@permission_required('manage_isp_routers')
def push_vlan_interfaces():
    all_vlan_ids = [m.vlan_id for m in VlanMapping.query.all() if m.vlan_id]
    if not all_vlan_ids:
        flash('No VLANs configured — nothing to push.', 'warning')
        return redirect(url_for('admin.isp_routers.admin_isp_routers'))
    ok = reset_vlan_interface_masks(all_vlan_ids)
    if ok:
        flash(
            f'VLAN interface config pushed to all switches for {len(all_vlan_ids)} VLAN(s).',
            'success',
        )
    else:
        flash('VLAN interface push failed on one or more switches — check logs.', 'warning')
    return redirect(url_for('admin.isp_routers.admin_isp_routers'))


@isp_routers_bp.route('/reapply-acl-blocks', methods=['POST'])
@login_required
@permission_required('manage_isp_routers')
def reapply_acl_blocks():
    baseline_ok = reset_acl_baseline()
    pushed, failed = reapply_all_ip_blocks()
    if baseline_ok and failed == 0:
        flash(f'ACL baseline pushed and {pushed} IP block(s) re-applied to all switches.', 'success')
    elif not baseline_ok:
        flash(f'ACL baseline push failed. {pushed} block(s) re-applied ({failed} failed).', 'warning')
    else:
        flash(f'ACL baseline pushed. {pushed} block(s) re-applied but {failed} failed.', 'warning')
    return redirect(url_for('admin.isp_routers.admin_isp_routers'))


@isp_routers_bp.route('/push-all-switch-config', methods=['POST'])
@login_required
@permission_required('manage_isp_routers')
def push_all_switch_config():
    import secrets as _secrets
    job_id = _secrets.token_hex(16)

    all_vlan_ids = [m.vlan_id for m in VlanMapping.query.all() if m.vlan_id]
    _push_job_write(job_id, {'status': 'running', 'message': 'Starting…'})

    def _run():
        from app import app as _app
        with _app.app_context():
            steps = []
            try:
                _push_job_write(job_id, {'status': 'running', 'message': 'Pushing PBR/NQA…'})
                pbr_ok = push_pbr_nqa_to_switches()
                steps.append(('PBR/NQA', pbr_ok))

                _push_job_write(job_id, {'status': 'running', 'message': 'Pushing ACL baseline…'})
                baseline_ok = reset_acl_baseline()
                steps.append(('ACL baseline', baseline_ok))

                if all_vlan_ids:
                    _push_job_write(job_id, {'status': 'running', 'message': 'Pushing VLAN interfaces…'})
                    vlan_ok = reset_vlan_interface_masks(all_vlan_ids)
                    steps.append(('VLAN interfaces', vlan_ok))

                _push_job_write(job_id, {'status': 'running', 'message': 'Re-applying IP blocks…'})
                pushed, failed = reapply_all_ip_blocks()
                steps.append(('IP blocks', failed == 0))

                all_ok = all(ok for _, ok in steps)
                if all_ok:
                    _push_job_write(job_id, {
                        'status': 'done', 'ok': True,
                        'message': (
                            f'All switch config pushed successfully. '
                            f'PBR/NQA ✓  ACL baseline ✓  VLAN interfaces ✓  '
                            f'IP blocks: {pushed} re-applied.'
                        ),
                    })
                else:
                    bad = [name for name, ok in steps if not ok]
                    _push_job_write(job_id, {
                        'status': 'done', 'ok': False,
                        'message': (
                            f'Push completed with errors in: {", ".join(bad)}. '
                            f'IP blocks: {pushed} pushed, {failed} failed. Check logs.'
                        ),
                    })
            except Exception as exc:
                logger.exception("push_all_switch_config background job failed")
                _push_job_write(job_id, {
                    'status': 'done', 'ok': False,
                    'message': f'Push failed with exception: {exc}',
                })

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({'job_id': job_id})


@isp_routers_bp.route('/push-all-switch-config/status/<job_id>', methods=['GET'])
@login_required
@permission_required('manage_isp_routers')
def push_all_switch_config_status(job_id):
    job = _push_job_read(job_id)
    if not job:
        return jsonify({'status': 'running', 'message': 'Starting…'})
    return jsonify({
        'status':  job['status'],
        'ok':      job.get('ok'),
        'message': job.get('message', ''),
    })