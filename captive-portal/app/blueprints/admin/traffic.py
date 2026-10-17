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
    """Independent, server-side paged DNS and NAT traffic tables.

    Filters travel in the URL rather than silently being restored from saved
    settings. A page with no filter parameters always starts unfiltered.
    Sorting/paging works on each table separately, for both JS and plain GETs.
    """
    from sqlalchemy import text

    valid_cols = {col for col, _ in ALL_COLUMNS}
    settings = {}
    if current_user.traffic_viewer_settings:
        try:
            data = json.loads(current_user.traffic_viewer_settings)
            if isinstance(data, dict):
                settings = data
        except (TypeError, ValueError):
            pass

    if request.args.get('reset') == '1':
        # Older versions persisted search filters in Admin.traffic_viewer_settings.
        # A plain link to /traffic would load these again. Explicitly remove them.
        try:
            admin = Admin.query.get(int(current_user.id))
            if admin:
                data = json.loads(admin.traffic_viewer_settings or '{}')
                if not isinstance(data, dict):
                    data = {}
                data.pop('filters', None)
                data.pop('sort_col', None)
                data.pop('sort_order', None)
                data.pop('dns_sort', None)
                data.pop('dns_order', None)
                data.pop('nat_sort', None)
                data.pop('nat_order', None)
                admin.traffic_viewer_settings = json.dumps(data)
                db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception('Unable to clear saved traffic filters')
            # Still display unfiltered results; do not allow stale filters back.
        return redirect(url_for('admin.traffic.traffic'))

    # Keep column and row-count preferences but never implicitly reapply an old
    # search. Values in the query string are the only active filters.
    raw_columns = request.args.getlist('columns') if 'columns' in request.args else settings.get('columns', _DEFAULT_COLUMNS)
    if not isinstance(raw_columns, (list, tuple)):
        raw_columns = _DEFAULT_COLUMNS
    selected_columns = [col for col in raw_columns if col in valid_cols]
    if not selected_columns:
        selected_columns = list(_DEFAULT_COLUMNS)

    raw_page_size = request.args.get('per_page', type=int)
    if raw_page_size is None:
        raw_page_size = settings.get('per_page', 50)
    try:
        per_page = min(max(int(raw_page_size), 10), 500)
    except (TypeError, ValueError):
        per_page = 50

    filters = {}
    for name, _ in ALL_COLUMNS:
        val = request.args.get('filter_' + name, '').strip()[:200]
        if val:
            filters[name] = val

    def sort_state(kind):
        col = request.args.get(kind + '_sort', 'lookup_timestamp')
        direction = request.args.get(kind + '_order', 'desc').lower()
        if col not in valid_cols:
            col = 'lookup_timestamp'
        if direction not in ('asc', 'desc'):
            direction = 'desc'
        page = request.args.get(kind + '_page', 1, type=int)
        page = min(max(page or 1, 1), 100000)
        return {'sort': col, 'order': direction, 'page': page}

    dns_state = sort_state('dns')
    nat_state = sort_state('nat')

    # Save layout only upon explicit form submission; never save active filters.
    # This also avoids DB writes during the 60-second AJAX auto-refresh.
    if request.args.get('save') == '1':
        try:
            admin = Admin.query.get(int(current_user.id))
            if admin:
                data = json.loads(admin.traffic_viewer_settings or '{}')
                if not isinstance(data, dict):
                    data = {}
                data.update(columns=selected_columns, per_page=per_page)
                data.pop('filters', None)
                admin.traffic_viewer_settings = json.dumps(data)
                db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception('Unable to save traffic viewer layout')

    self_ips = sorted(_pi_self_ips() | _infra_ips())
    # A cheap probe avoids COUNT(*) over unbounded log tables on every refresh.
    has_dns = db.session.execute(text('SELECT EXISTS(SELECT 1 FROM dns_lookups LIMIT 1)')).scalar()
    has_nat = db.session.execute(text('SELECT EXISTS(SELECT 1 FROM nat_sessions LIMIT 1)')).scalar()
    using_dns_fallback = not (has_dns or has_nat)

    dns_base = '''
        SELECT l.id AS lookup_id,
               l.lookup_timestamp AS lookup_timestamp,
               host(l.client_ip::inet) AS client_ip,
               l.client_port AS lan_src_port,
               l.domain_name AS domain_name,
               host(l.resolved_ip::inet) AS domain_ip,
               NULL::text AS src_mac,
               NULL::integer AS wan_src_port,
               NULL::integer AS dst_port,
               'dns'::text AS traffic_source
        FROM dns_lookups l
    '''
    nat_base = '''
        SELECT n.session_id AS lookup_id,
               n.session_start AS lookup_timestamp,
               host(n.src_ip::inet) AS client_ip,
               n.src_port AS lan_src_port,
               n.domain_name AS domain_name,
               host(n.dst_ip::inet) AS domain_ip,
               n.src_mac::text AS src_mac,
               NULL::integer AS wan_src_port,
               n.dst_port AS dst_port,
               'nat'::text AS traffic_source
        FROM nat_sessions_enriched n
    '''
    fallback_base = '''
        SELECT p.session_id AS lookup_id,
               p.session_start AS lookup_timestamp,
               p.src_ip::text AS client_ip,
               NULL::integer AS lan_src_port,
               p.domain_name AS domain_name,
               NULL::text AS domain_ip,
               p.src_mac::text AS src_mac,
               NULL::integer AS wan_src_port,
               p.dst_port AS dst_port,
               'pihole'::text AS traffic_source,
               p.user_email, p.user_first_name, p.user_last_name
        FROM pihole_blocked_enriched p
    '''
    # Only columns that exist in the initial (pre-ownership-join) row can be
    # searched/sorted before pagination. This matters for large traffic tables.
    raw_cols = set(valid_cols) - {'user_email', 'user_first_name', 'user_last_name'}
    base_cols = {'dns': raw_cols - {'src_mac'}, 'nat': raw_cols, 'pihole': raw_cols}

    def filter_sql(alias, active, params):
        clauses = []
        for index, (name, value) in enumerate(active.items()):
            key = 'search_' + str(index)
            col = f'{alias}.{name}'  # name comes from the fixed ALL_COLUMNS whitelist
            if name == 'lookup_timestamp':
                lower = value.lower()
                if ' to ' in lower:
                    parts = lower.split(' to ', 1)
                    start, end = _parse_date(parts[0]), _parse_date(parts[1])
                    if start and end:
                        clauses += [f'{col} >= :{key}_start', f'{col} < :{key}_end']
                        params[key + '_start'] = start
                        params[key + '_end'] = end + timedelta(days=1)
                    else:
                        clauses.append('FALSE')
                elif value.startswith(('>', '<')):
                    date = _parse_date(value[1:])
                    if date:
                        clauses.append(f'{col} {value[0]} :{key}')
                        params[key] = date
                    else:
                        clauses.append('FALSE')
                else:
                    date = _parse_date(value)
                    if date:
                        clauses += [f'{col} >= :{key}_start', f'{col} < :{key}_end']
                        params[key + '_start'] = date
                        params[key + '_end'] = date + timedelta(days=1)
                    else:
                        clauses.append('FALSE')
            else:
                params[key] = value if '%' in value else '%' + value + '%'
                clauses.append(f'CAST({col} AS text) ILIKE :{key}')
        return clauses

    def order_sql(alias, state):
        col = state['sort']
        direction = state['order'].upper()
        # Timestamp + ID provide stable ties when paginating.
        sort_value = f'({alias}.{col})::inet' if col in ('client_ip', 'domain_ip') else f'{alias}.{col}'
        return (f'{sort_value} {direction} NULLS LAST, '
                f'{alias}.lookup_timestamp DESC NULLS LAST, '
                f'{alias}.lookup_id DESC')

    enrichment_joins = '''
        LEFT JOIN LATERAL (
            SELECT lease.mac_address FROM ip_leases lease
            WHERE b.traffic_source = 'dns'
              AND host(lease.ip_address::inet) = b.client_ip
              AND lease.lease_start <= b.lookup_timestamp
              AND lease.lease_expiry > b.lookup_timestamp
            ORDER BY lease.lease_start DESC LIMIT 1
        ) lse ON TRUE
        LEFT JOIN LATERAL (
            SELECT own.user_id FROM device_ownership own
            WHERE own.mac_address = COALESCE(b.src_mac, lse.mac_address::text)
              AND own.start_datetime <= b.lookup_timestamp
              AND (own.end_datetime IS NULL OR own.end_datetime > b.lookup_timestamp)
            ORDER BY own.start_datetime DESC LIMIT 1
        ) own ON TRUE
        LEFT JOIN users u ON u.id = own.user_id
    '''
    enriched_select = '''
        SELECT b.lookup_id, b.lookup_timestamp, b.client_ip, b.lan_src_port,
               b.domain_name, b.domain_ip,
               COALESCE(b.src_mac, lse.mac_address::text)::text AS src_mac,
               u.email AS user_email, u.first_name AS user_first_name,
               u.last_name AS user_last_name,
               b.wan_src_port, b.dst_port, b.traffic_source
        FROM {base} b
        {joins}
    '''

    def fetch_table(kind, state):
        source = 'pihole' if kind == 'dns' and using_dns_fallback else kind
        if kind == 'nat' and using_dns_fallback:
            return {'rows': [], 'has_next': False, 'error': None, **state}
        base = {'dns': dns_base, 'nat': nat_base, 'pihole': fallback_base}[source]
        params = {'limit': per_page + 1, 'offset': (state['page'] - 1) * per_page}
        can_prepage = set(filters).issubset(base_cols[source]) and state['sort'] in base_cols[source]
        try:
            if source == 'pihole':
                # Fallback view already contains user fields (there are no
                # native DNS/NAT records yet).
                predicate = filter_sql('b', filters, params)
                if self_ips:
                    params['self_ips'] = self_ips
                    predicate.append('b.client_ip <> ALL(:self_ips)')
                sql = f'''
                    SELECT * FROM ({base}) b
                    WHERE {' AND '.join(predicate) if predicate else 'TRUE'}
                    ORDER BY {order_sql('b', state)}
                    LIMIT :limit OFFSET :offset
                '''
            elif can_prepage:
                predicate = filter_sql('b', filters, params)
                if self_ips:
                    params['self_ips'] = self_ips
                    predicate.append('b.client_ip <> ALL(:self_ips)')
                sql = f'''
                    WITH page AS MATERIALIZED (
                        SELECT * FROM ({base}) b
                        WHERE {' AND '.join(predicate) if predicate else 'TRUE'}
                        ORDER BY {order_sql('b', state)}
                        LIMIT :limit OFFSET :offset
                    )
                    SELECT * FROM (
                        {enriched_select.format(base='page', joins=enrichment_joins)}
                    ) e
                    ORDER BY {order_sql('e', state)}
                '''
            else:
                # User/MAC enrichment filters and sorts must run before LIMIT.
                # These are slower than the common indexed timestamp path.
                predicate = filter_sql('e', filters, params)
                if self_ips:
                    params['self_ips'] = self_ips
                    predicate.append('e.client_ip <> ALL(:self_ips)')
                enriched = enriched_select.format(base=f'({base})', joins=enrichment_joins)
                sql = f'''
                    SELECT * FROM ({enriched}) e
                    WHERE {' AND '.join(predicate) if predicate else 'TRUE'}
                    ORDER BY {order_sql('e', state)}
                    LIMIT :limit OFFSET :offset
                '''
            # Bound slow user-enrichment sorts instead of holding a web worker
            # indefinitely on a large DNS/NAT history.
            db.session.execute(text("SET LOCAL statement_timeout = '8s'"))
            result = db.session.execute(text(sql), params)
            rows = [dict(row._mapping) for row in result]
            has_next = len(rows) > per_page
            return {'rows': rows[:per_page], 'has_next': has_next,
                    'error': None, **state}
        except Exception as exc:
            db.session.rollback()
            logger.exception('Traffic viewer %s query failed', kind)
            return {'rows': [], 'has_next': False,
                    'error': 'Unable to load this table. Please try again or narrow your filters.',
                    **state}

    dns = fetch_table('dns', dns_state)
    nat = fetch_table('nat', nat_state)
    logger.info('Traffic viewer: filters=%s dns=%d nat=%d, pages=%d/%d',
                filters, len(dns['rows']), len(nat['rows']),
                dns['page'], nat['page'])

    # All links include explicit current filters; no stale saved state can be
    # reintroduced by a header click, refresh, pagination, or a page reload.
    link_args = {'per_page': per_page, 'columns': selected_columns}
    for name, value in filters.items():
        link_args['filter_' + name] = value
    for kind, state in (('dns', dns), ('nat', nat)):
        link_args[kind + '_page'] = state['page']
        link_args[kind + '_sort'] = state['sort']
        link_args[kind + '_order'] = state['order']

    def link_for(kind, *, col=None, page=None):
        args = dict(link_args)
        if col is not None:
            args[kind + '_sort'] = col
            args[kind + '_order'] = (
                ('asc' if args[kind + '_order'] == 'desc' else 'desc')
                if args[kind + '_sort'] == col else 'desc'
            )
            args[kind + '_page'] = 1
        if page is not None:
            args[kind + '_page'] = page
        return url_for('admin.traffic.traffic', **args)

    return render_template(
        'admin_traffic.html', all_columns=ALL_COLUMNS,
        selected_columns=selected_columns, filters=filters,
        per_page=per_page, using_dns_fallback=using_dns_fallback,
        dns=dns, nat=nat, link_for=link_for,
    )
