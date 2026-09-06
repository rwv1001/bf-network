"""
Admin — Traffic Viewer (spec section 12 / CODEBASE section 10).

Routes:
  GET /admin/traffic    DNS lookup traffic enriched with user and NAT port data
"""

import json
import logging
import os

from datetime import datetime, timedelta

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import Admin
from core.auth import permission_required

logger = logging.getLogger(__name__)

traffic_bp = Blueprint('traffic', __name__)


def _pi_self_ips(_cache={}):
    """This host's IPs (web runs host-network, so these are the Pi's own addresses)."""
    import time as _time
    now = _time.time()
    if _cache.get('ts', 0) + 300 > now:
        return _cache['ips']
    import socket as _socket, fcntl as _fcntl, struct as _struct
    ips = {'127.0.0.1', '::1'}
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            for _idx, ifname in _socket.if_nameindex():
                try:
                    ips.add(_socket.inet_ntoa(_fcntl.ioctl(
                        s.fileno(), 0x8915,  # SIOCGIFADDR
                        _struct.pack('256s', ifname.encode()[:15]))[20:24]))
                except OSError:
                    continue
    except Exception:
        pass
    for env in ('PORTAL_IP', 'HIJACK_DNS_IP'):
        val = os.getenv(env, '').strip()
        if val:
            ips.add(val)
    _cache.update(ts=now, ips=ips)
    return ips


def _infra_ips(_cache={}):
    """Router/switch/infrastructure addresses, derived from env and the ISP router table."""
    import time as _time
    now = _time.time()
    if _cache.get('ts', 0) + 300 > now:
        return _cache['ips']
    ips = set()
    for env in ('MGMT_GATEWAY', 'UNREGISTERED_GW', 'UDM_HOST', 'TEL_HOST'):
        val = os.getenv(env, '').strip()
        if val:
            ips.add(val)
    ips.update(h for h in os.getenv('SWITCH_HOSTS', '').split() if h)
    octets = [int(b) for b in os.getenv('SWITCH_HOSTS_BYTES', '').split(',') if b.strip().isdigit()]
    if not octets:
        # fall back to the last octet of each switch management IP
        for host in os.getenv('SWITCH_HOSTS', '').split():
            tail = host.rsplit('.', 1)[-1]
            if tail.isdigit():
                octets.append(int(tail))
    net_word = os.getenv('NETWORK_WORD', '192.168').strip()
    try:
        import ipaddress
        from models import ISPRouter, VlanMapping
        for vm in VlanMapping.query.all():
            if vm.vlan_id:
                for octet in octets:
                    ips.add(f'{net_word}.{vm.vlan_id}.{octet}')
        for router in ISPRouter.query.all():
            if router.gateway_ip:
                ips.add(router.gateway_ip.strip())
            if router.switch_host:
                ips.add(router.switch_host.strip())
            if router.subnet:
                net = ipaddress.ip_network(router.subnet, strict=False)
                for octet in octets:
                    ips.add(str(net.network_address + octet))
    except Exception as exc:
        logger.debug('infra IP derivation from DB failed: %s', exc)
    _cache.update(ts=now, ips=ips)
    return ips

ALL_COLUMNS = [
    ('lookup_id',        'ID'),
    ('lookup_timestamp', 'Time'),
    ('client_ip',        'Client IP'),
    ('lan_src_port',     'LAN Port'),
    ('domain_name',      'Domain'),
    ('domain_ip',        'Domain IP'),
    ('src_mac',          'MAC Address'),
    ('user_email',       'User Email'),
    ('user_first_name',  'First Name'),
    ('user_last_name',   'Last Name'),
    ('wan_src_port',     'WAN Port'),
    ('dst_port',         'Dest Port'),
    ('traffic_source', 'Source'),
]

_DEFAULT_COLUMNS = [
    'lookup_timestamp', 'client_ip', 'domain_name', 'domain_ip',
    'user_email', 'user_first_name', 'dst_port',
]


def _parse_date(s: str):
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    return None


@traffic_bp.route('/traffic')
@login_required
@permission_required('view_traffic')
def traffic():
    valid_column_names = {col[0] for col in ALL_COLUMNS}

    # Load saved settings for current admin
    saved_settings = {}
    if current_user.traffic_viewer_settings:
        try:
            saved_settings = json.loads(current_user.traffic_viewer_settings)
        except Exception:
            saved_settings = {}

    has_query_params = bool(
        request.args.get('columns') or
        request.args.get('sort') or
        request.args.get('order') or
        request.args.get('per_page') or
        any(request.args.get(f'filter_{col[0]}') for col in ALL_COLUMNS)
    )

    # Selected columns
    if has_query_params:
        selected_columns = request.args.getlist('columns') or _DEFAULT_COLUMNS
    else:
        selected_columns = saved_settings.get('columns', _DEFAULT_COLUMNS)
    selected_columns = [c for c in selected_columns if c in valid_column_names]
    if not selected_columns:
        selected_columns = _DEFAULT_COLUMNS

    # Filters
    filters = {}    
    for col_name, _ in ALL_COLUMNS:
        if has_query_params:
            filter_value = request.args.get(f'filter_{col_name}', '').strip()
        else:
            filter_value = saved_settings.get('filters', {}).get(col_name, '')
        if filter_value:
            filters[col_name] = filter_value

    # Pagination
    page = request.args.get('page', 1, type=int)
    if has_query_params and 'per_page' in request.args:
        per_page = request.args.get('per_page', 50, type=int)
    else:
        per_page = saved_settings.get('per_page', 50)
    per_page = min(max(per_page, 10), 500)

    # Sorting
    if has_query_params and ('sort' in request.args or 'order' in request.args):
        sort_col   = request.args.get('sort', 'lookup_timestamp')
        sort_order = request.args.get('order', 'desc')
    else:
        sort_col   = saved_settings.get('sort_col', 'lookup_timestamp')
        sort_order = saved_settings.get('sort_order', 'desc')

    if sort_col not in valid_column_names:
        sort_col = 'lookup_timestamp'
    if sort_order not in ('asc', 'desc'):
        sort_order = 'desc'

    # Save settings
    if has_query_params:
        current_settings = {
            'columns':    selected_columns,
            'filters':    filters,
            'per_page':   per_page,
            'sort_col':   sort_col,
            'sort_order': sort_order,
        }
        try:
            admin = Admin.query.get(int(current_user.id))
            if admin:
                # Preserve dashboard_hidden_sections if already stored
                existing = {}
                if admin.traffic_viewer_settings:
                    try:
                        existing = json.loads(admin.traffic_viewer_settings)
                    except Exception:
                        pass
                existing.update(current_settings)
                admin.traffic_viewer_settings = json.dumps(existing)
                db.session.commit()
        except Exception as exc:
            logger.warning("Failed to save traffic viewer settings: %s", exc)

    # Build SQL WHERE clause
    from sqlalchemy import text
    select_cols = ['session_id'] + [c for c in selected_columns if c != 'session_id']
    select_clause = ', '.join(select_cols)



    where_clauses = []
    params = {}
    param_counter = 0

    for col_name, filter_value in filters.items():
        if col_name in ('session_start', 'session_end', 'lookup_timestamp'):
            if ' to ' in filter_value.lower():
                parts = filter_value.lower().split(' to ')
                if len(parts) == 2:
                    start_dt = _parse_date(parts[0])
                    end_dt   = _parse_date(parts[1])
                    if start_dt and end_dt:
                        param_counter += 1
                        where_clauses.append(f"{col_name} >= :date_start_{param_counter}")
                        params[f'date_start_{param_counter}'] = start_dt
                        param_counter += 1
                        where_clauses.append(f"{col_name} < :date_end_{param_counter}")
                        params[f'date_end_{param_counter}'] = end_dt + timedelta(days=1)
            elif filter_value.startswith('>'):
                dt = _parse_date(filter_value[1:])
                if dt:
                    param_counter += 1
                    where_clauses.append(f"{col_name} > :date_{param_counter}")
                    params[f'date_{param_counter}'] = dt
            elif filter_value.startswith('<'):
                dt = _parse_date(filter_value[1:])
                if dt:
                    param_counter += 1
                    where_clauses.append(f"{col_name} < :date_{param_counter}")
                    params[f'date_{param_counter}'] = dt
            else:
                dt = _parse_date(filter_value)
                if dt:
                    param_counter += 1
                    where_clauses.append(f"{col_name} >= :date_start_{param_counter}")
                    params[f'date_start_{param_counter}'] = dt
                    param_counter += 1
                    where_clauses.append(f"{col_name} < :date_end_{param_counter}")
                    params[f'date_end_{param_counter}'] = dt + timedelta(days=1)
        else:
            param_counter += 1
            param_name = f'filter_{param_counter}'
            where_clauses.append(f"CAST({col_name} AS TEXT) ILIKE :{param_name}")
            params[param_name] = (
                filter_value if '%' in filter_value else f'%{filter_value}%'
            )    

    where_clause = ' AND '.join(where_clauses) if where_clauses else '1=1'

    from sqlalchemy import text as _text

    dns_count = db.session.execute(_text("SELECT COUNT(*) FROM dns_lookups")).scalar() or 0
    nat_count = db.session.execute(_text("SELECT COUNT(*) FROM nat_sessions")).scalar() or 0
    using_dns_fallback = (dns_count == 0 and nat_count == 0)
    source_view = "pihole_blocked_enriched" if using_dns_fallback else "traffic_combined"

    if using_dns_fallback:
        ip_col = 'src_ip'
    else:
        ip_col = 'client_ip'
    self_ips = sorted(_pi_self_ips() | _infra_ips())
    self_params = {}
    placeholders = []
    for i, ip in enumerate(self_ips):
        self_params[f'self_ip_{i}'] = ip
        placeholders.append(f':self_ip_{i}')
    where_clause += f" AND CAST({ip_col} AS TEXT) NOT IN ({', '.join(placeholders)})"
    params.update(self_params)

    # ====================== DEBUG: SQL Queries ======================
    logger.info("=" * 80)
    logger.info("=== TRAFFIC VIEWER DEBUG ===")
    logger.info(f"has_query_params: {has_query_params}")
    logger.info(f"Filters being applied: {filters}")
    logger.info("source_view=%s where=%s", source_view, where_clause)
    # ================================================================

    # pihole_blocked_enriched has the same column names for shared columns, but
    # not lookup_id/lan_src_port/domain_ip/wan_src_port; map these for that view.
    if using_dns_fallback:
        # remap pihole columns into the new naming scheme
        select_cols_sql = """
            session_id   AS lookup_id,
            session_start AS lookup_timestamp,
            src_ip       AS client_ip,
            NULL::INTEGER AS lan_src_port,
            domain_name,
            NULL::TEXT   AS domain_ip,
            src_mac,
            user_email,
            user_first_name,
            user_last_name,
            NULL::INTEGER AS wan_src_port,
            dst_port,
            'pihole'::text AS traffic_source
        """
        valid_sort = {
            'lookup_id': 'session_id', 'lookup_timestamp': 'session_start',
            'client_ip': 'src_ip', 'domain_name': 'domain_name',
            'user_email': 'user_email', 'user_first_name': 'user_first_name',
            'user_last_name': 'user_last_name', 'src_mac': 'src_mac',
        }
        effective_sort = valid_sort.get(sort_col, 'session_start')
    else:
        select_cols_sql = ', '.join(c for c, _ in ALL_COLUMNS)
        effective_sort = sort_col if sort_col in {c for c, _ in ALL_COLUMNS} else 'lookup_timestamp'

    count_sql = f"SELECT COUNT(*) FROM {source_view} WHERE {where_clause}"
    logger.info("COUNT SQL:")
    logger.info(count_sql)
    logger.info(f"PARAMS: {params}")

    total = db.session.execute(
        _text(f"SELECT COUNT(*) FROM {source_view} WHERE {where_clause}"),
        params,
    ).scalar()

    offset = (page - 1) * per_page
    order_clause = f"{sort_col} {sort_order.upper()}"

    main_sql = f"""
        SELECT {select_cols_sql}
        FROM {source_view}
        WHERE {where_clause}
        ORDER BY {effective_sort} {sort_order.upper()}
        LIMIT :limit OFFSET :offset
    """

    logger.info("MAIN SELECT SQL:")
    logger.info(main_sql.strip())
    exec_params = {**params, 'limit': per_page, 'offset': offset}
    logger.info(f"EXEC PARAMS: {exec_params}")


    result = db.session.execute(_text(main_sql), exec_params)
    rows = [dict(row._mapping) for row in result]

    logger.info(f"Results: total={total}, rows returned={len(rows)}")
    logger.info("=" * 80)

    total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0

    return render_template(
        'admin_traffic.html',
        all_columns=ALL_COLUMNS,
        selected_columns=selected_columns,
        filters=filters,
        rows=rows,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        sort_col=sort_col,
        sort_order=sort_order,
        using_dns_fallback=using_dns_fallback,
    )