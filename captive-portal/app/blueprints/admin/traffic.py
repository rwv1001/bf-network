"""
Admin — Traffic Viewer (spec section 12 / CODEBASE section 10).

Routes:
  GET /admin/traffic    traffic viewer with NAT sessions enriched data
"""

import json
import logging

from datetime import datetime, timedelta

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import Admin
from core.auth import permission_required

logger = logging.getLogger(__name__)

traffic_bp = Blueprint('traffic', __name__)

ALL_COLUMNS = [
    ('session_id',         'Session ID'),
    ('session_start',      'Start Time'),
    ('session_end',        'End Time'),
    ('src_ip',             'Source IP'),
    ('src_port',           'Source Port'),
    ('user_email',         'User Email'),
    ('user_first_name',    'First Name'),
    ('user_last_name',     'Last Name'),
    ('registration_status','Status'),
    ('dst_ip',             'Destination IP'),
    ('dst_port',           'Dest Port'),
    ('domain_name',        'Domain'),
    ('dns_query_count',    'DNS Queries'),
    ('packet_count',       'Packets'),
    ('duration_seconds',   'Duration (s)'),
    ('switch_iface',       'Switch Port'),
    ('src_mac',            'MAC Address'),
    ('switch_host',        'Switch IP'),
]

_DEFAULT_COLUMNS = [
    'session_start', 'src_ip', 'user_email', 'user_first_name',
    'dst_ip', 'domain_name', 'packet_count', 'duration_seconds',
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
        sort_col   = request.args.get('sort', 'session_start')
        sort_order = request.args.get('order', 'desc')
    else:
        sort_col   = saved_settings.get('sort_col', 'session_start')
        sort_order = saved_settings.get('sort_order', 'desc')

    if sort_col not in valid_column_names:
        sort_col = 'session_start'
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
        if col_name in ('session_start', 'session_end'):
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

    # ====================== DEBUG: SQL Queries ======================
    logger.info("=" * 80)
    logger.info("=== TRAFFIC VIEWER DEBUG ===")
    logger.info(f"has_query_params: {has_query_params}")
    logger.info(f"Filters being applied: {filters}")

    count_sql = f"SELECT COUNT(*) FROM nat_sessions_enriched WHERE {where_clause}"
    logger.info("COUNT SQL:")
    logger.info(count_sql)
    logger.info(f"PARAMS: {params}")
    # ================================================================

    from sqlalchemy import text as _text
    total = db.session.execute(
        _text(f"SELECT COUNT(*) FROM nat_sessions_enriched WHERE {where_clause}"),
        params,
    ).scalar()

    offset = (page - 1) * per_page
    order_clause = f"{sort_col} {sort_order.upper()}"

    main_sql = f"""
        SELECT {select_clause}
        FROM nat_sessions_enriched
        WHERE {where_clause}
        ORDER BY {order_clause}
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
    )