"""
Admin — Firmware Management (spec section 12 / CODEBASE section 12).

Routes:
  GET      /admin/firmware                      firmware status page
  GET/POST /admin/firmware/preflight/<action>   pre-flight checklist
  GET      /admin/firmware/do/<action>          streaming page
  GET      /admin/firmware/stream/<action>      SSE stream
  POST     /admin/firmware/mark-done/<action>   record completed op in session
  GET      /admin/firmware/verify-last          verify last op (test mode only)
"""

import json
import logging
import os
import subprocess

from flask import (
    Blueprint, Response, flash, jsonify, redirect,
    render_template, request, session, stream_with_context, url_for,
)
from flask_login import login_required

from core.auth import permission_required

logger = logging.getLogger(__name__)

firmware_bp = Blueprint('firmware', __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_firmware_script(action, extra_args=None):
    git_repo_dir = os.environ['GIT_REPO_DIR']
    script_path  = '/scripts/firmware-manager.sh'
    cmd = ['/bin/bash', script_path, action] + (extra_args or [])
    env = dict(os.environ)
    env['GIT_REPO_DIR'] = git_repo_dir
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)


def _load_commit_manifest(tree_hash, file_hash):
    if not tree_hash or not file_hash:
        return None
    git_repo_dir = os.environ['GIT_REPO_DIR']
    candidates = [file_hash[:7], file_hash]
    for name in candidates:
        blob_path = f'captive-portal/commit-migrations/{name}.json'
        try:
            result = subprocess.run(
                ['git', '-C', git_repo_dir, 'show', f'{tree_hash}:{blob_path}'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except Exception:
            pass
    return None


def _read_env_file() -> dict:
    git_repo_dir = os.environ['GIT_REPO_DIR']
    env_path = os.path.join(git_repo_dir, 'captive-portal', '.env')
    result = {}
    if not os.path.exists(env_path):
        return result
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, val = line.partition('=')
                result[key.strip()] = val.strip()
    return result


def _write_env_vars(new_vars: dict) -> None:
    if not new_vars:
        return
    git_repo_dir = os.environ['GIT_REPO_DIR']
    env_path = os.path.join(git_repo_dir, 'captive-portal', '.env')
    lines = []
    if os.path.exists(env_path):
        with open(env_path) as f:
            lines = f.readlines()
    updated = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '=' in stripped:
            key = stripped.split('=', 1)[0].strip()
            if key in new_vars:
                new_lines.append(f'{key}={new_vars[key]}\n')
                updated.add(key)
                continue
        new_lines.append(line)
    for key, value in new_vars.items():
        if key not in updated:
            new_lines.append(f'{key}={value}\n')
    with open(env_path, 'w') as f:
        f.writelines(new_lines)


def _remove_env_vars(keys) -> None:
    keys = set(keys)
    if not keys:
        return
    git_repo_dir = os.environ['GIT_REPO_DIR']
    env_path = os.path.join(git_repo_dir, 'captive-portal', '.env')
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '=' in stripped:
            key = stripped.split('=', 1)[0].strip()
            if key in keys:
                continue
        new_lines.append(line)
    with open(env_path, 'w') as f:
        f.writelines(new_lines)


def _run_db_verify_check(check: dict) -> dict:
    from extensions import db
    from sqlalchemy import text
    ctype = check.get('type', '')
    try:
        if ctype in ('column', 'column_absent'):
            tbl = check.get('table', '')
            col = check.get('column', '')
            exists = bool(db.session.execute(
                text("SELECT COUNT(*) FROM information_schema.columns "
                     "WHERE table_name = :t AND column_name = :c"),
                {'t': tbl, 'c': col},
            ).scalar())
            want_present = (ctype == 'column')
            passed = exists if want_present else not exists
            if want_present:
                detail = f"Column {tbl}.{col} exists ✓" if passed else f"Column {tbl}.{col} MISSING ✗"
            else:
                detail = f"Column {tbl}.{col} absent ✓" if passed else f"Column {tbl}.{col} still present ✗"
            return {'category': 'db', 'name': f"{tbl}.{col}", 'pass': passed, 'detail': detail}

        elif ctype in ('table', 'table_absent'):
            name = check.get('name', '')
            exists = bool(db.session.execute(
                text("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = :n"),
                {'n': name},
            ).scalar())
            want_present = (ctype == 'table')
            passed = exists if want_present else not exists
            if want_present:
                detail = f"Table {name} exists ✓" if passed else f"Table {name} MISSING ✗"
            else:
                detail = f"Table {name} absent ✓" if passed else f"Table {name} still present ✗"
            return {'category': 'db', 'name': name, 'pass': passed, 'detail': detail}

        else:
            return {'category': 'db', 'name': ctype, 'pass': False,
                    'detail': f"Unknown check type: {ctype!r}"}
    except Exception as exc:
        return {'category': 'db', 'name': str(check.get('name', check)),
                'pass': False, 'detail': f"Error running check: {exc}"}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@firmware_bp.route('/firmware')
@login_required
@permission_required('manage_firmware')
def admin_firmware():
    status = {}
    error  = None
    next_manifest    = None
    current_manifest = None
    try:
        result = _run_firmware_script('status')
        if result.returncode == 0:
            status = json.loads(result.stdout)
            next_manifest    = _load_commit_manifest(status.get('next_full'),    status.get('current_full'))
            current_manifest = _load_commit_manifest(status.get('current_full'), status.get('prev_full'))
        else:
            error = (result.stderr or result.stdout or 'Script returned non-zero exit').strip()
    except Exception as exc:
        error = str(exc)
    return render_template(
        'admin_firmware.html',
        status=status,
        error=error,
        next_manifest=next_manifest,
        current_manifest=current_manifest,
        last_op=session.get('firmware_last_op'),
        test_enabled=os.getenv('FIRMWARE_TEST_ENABLED', '').lower() not in ('', '0', 'false', 'no'),
        commits_ahead_count=len(status.get('commits_ahead', [])),
    )


@firmware_bp.route('/firmware/preflight/<action>', methods=['GET', 'POST'])
@login_required
@permission_required('manage_firmware')
def preflight(action):
    if action not in ('update', 'rollback', 'update-latest'):
        return jsonify({'error': 'Invalid action'}), 400

    status_result = _run_firmware_script('status')
    if status_result.returncode != 0:
        flash('Could not read git status — is the repo accessible?', 'danger')
        return redirect(url_for('admin.firmware.admin_firmware'))
    status = json.loads(status_result.stdout)

    if action == 'update':
        target_hash    = status.get('next_full')
        target_short   = status.get('next_short')
        target_subject = status.get('next_subject')
        if not target_hash:
            flash('Already on the latest commit — nothing to update.', 'warning')
            return redirect(url_for('admin.firmware.admin_firmware'))
        manifest = _load_commit_manifest(target_hash, status.get('current_full'))

    elif action == 'update-latest':
        commits_ahead  = status.get('commits_ahead', [])
        target_hash    = status.get('latest_full')
        target_short   = status.get('latest_short')
        target_subject = status.get('latest_subject')
        if not commits_ahead or not target_hash:
            flash('Already on the latest commit — nothing to update.', 'warning')
            return redirect(url_for('admin.firmware.admin_firmware'))
        agg_add, agg_remove = {}, {}
        migration_count = 0
        for commit in commits_ahead:
            m = _load_commit_manifest(commit['full'], commit['from_full'])
            if not m:
                continue
            for entry in (m.get('env') or {}).get('add', []):
                k = entry.get('key', '')
                if k and k not in agg_add:
                    agg_add[k] = entry
            for entry in (m.get('env') or {}).get('remove', []):
                if isinstance(entry, dict):
                    k = entry.get('key', '')
                    if k and k not in agg_remove:
                        agg_remove[k] = entry
            if (m.get('db') or {}).get('up'):
                migration_count += 1
        manifest = {
            'description': f'Update {len(commits_ahead)} commit(s) to {target_short}: {target_subject}',
            'env': {'add': list(agg_add.values()), 'remove': list(agg_remove.values())},
            'db': {'up': f'({migration_count} migration script(s) will run in sequence)'} if migration_count else None,
        }

    else:  # rollback
        target_hash    = status.get('current_full')
        target_short   = status.get('current_short')
        target_subject = status.get('current_subject')
        if not status.get('prev_full'):
            flash('Already on the first commit — cannot roll back.', 'warning')
            return redirect(url_for('admin.firmware.admin_firmware'))
        manifest = _load_commit_manifest(target_hash, status.get('prev_full'))

    current_env = _read_env_file()

    if request.method == 'POST':
        new_vars = {}
        errors   = []
        if manifest and action in ('update', 'update-latest'):
            for entry in manifest.get('env', {}).get('add', []):
                key = entry['key']
                val = request.form.get(f'env_{key}', '').strip()
                if not val and entry.get('required'):
                    val = current_env.get(key, '')
                    if not val:
                        errors.append(f'{key} is required.')
                if val:
                    new_vars[key] = val

        if manifest and action == 'rollback':
            for entry in manifest.get('env', {}).get('remove', []):
                if not isinstance(entry, dict):
                    continue
                key = entry.get('key', '')
                if not key:
                    continue
                val = request.form.get(f'env_restore_{key}', '').strip()
                if not val:
                    val = current_env.get(key, '')
                    if not val and entry.get('required'):
                        errors.append(f'{key} is required for rollback.')
                if val:
                    new_vars[key] = val

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template(
                'admin_firmware_preflight.html',
                action=action, status=status, manifest=manifest,
                target_hash=target_hash, target_short=target_short,
                target_subject=target_subject, current_env=current_env,
            )

        if new_vars:
            try:
                _write_env_vars(new_vars)
            except Exception as exc:
                flash(f'Failed to write .env: {exc}', 'danger')
                return redirect(url_for('admin.firmware.admin_firmware'))

        session['firmware_preflight_approved'] = action
        session['firmware_preflight_hash']     = target_hash
        return redirect(url_for('admin.firmware.do', action=action))

    return render_template(
        'admin_firmware_preflight.html',
        action=action, status=status, manifest=manifest,
        target_hash=target_hash, target_short=target_short,
        target_subject=target_subject, current_env=current_env,
    )


@firmware_bp.route('/firmware/do/<action>')
@login_required
@permission_required('manage_firmware')
def do(action):
    if action not in ('update', 'rollback', 'update-latest'):
        return redirect(url_for('admin.firmware.admin_firmware'))
    approved = session.get('firmware_preflight_approved')
    if approved != action:
        flash('Please complete the pre-flight checklist first.', 'warning')
        return redirect(url_for('admin.firmware.preflight', action=action))
    return render_template('admin_firmware_do.html', action=action)


@firmware_bp.route('/firmware/stream/<action>')
@login_required
@permission_required('manage_firmware')
def stream(action):
    if action not in ('update', 'rollback', 'update-latest'):
        return jsonify({'error': 'Invalid action'}), 400

    if session.get('firmware_preflight_approved') != action:
        def _denied():
            yield "data: ERROR: Pre-flight not completed.\n\n"
            yield "data: __EXIT__:1\n\n"
        return Response(stream_with_context(_denied()),
                        mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

    session.pop('firmware_preflight_approved', None)
    session.pop('firmware_preflight_hash', None)

    def generate():
        git_repo_dir = os.environ['GIT_REPO_DIR']
        script_env   = dict(os.environ)
        script_env['GIT_REPO_DIR'] = git_repo_dir

        def emit(line):
            return f"data: {line}\n\n"

        def stream_proc(cmd, cwd=None, env=None):
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=cwd, env=(env or script_env),
            )
            for ln in proc.stdout:
                yield emit(ln.rstrip())
            proc.wait()
            return proc.returncode

        try:
            status_result = _run_firmware_script('status')
            if status_result.returncode != 0:
                yield emit("ERROR: Could not read git status.")
                yield emit("__EXIT__:1")
                return
            status = json.loads(status_result.stdout)

            if action == 'update':
                next_hash    = status.get('next_full')
                changed_dirs = status.get('forward_dirs', [])
                if not next_hash:
                    yield emit("ERROR: No next commit available.")
                    yield emit("__EXIT__:1")
                    return

                yield emit(f"=== Step 1/3: Checking out {status.get('next_short')} ===")
                rc = yield from stream_proc(['git', '-C', git_repo_dir, 'checkout', '-f', next_hash])
                if rc != 0:
                    yield emit("ERROR: git checkout failed — aborting.")
                    yield emit("__EXIT__:1")
                    return
                yield emit("")

                manifest = _load_commit_manifest(next_hash, status.get('current_full'))
                env_remove_entries = (manifest or {}).get('env', {}).get('remove', [])
                env_remove_keys = [e['key'] if isinstance(e, dict) else e
                                   for e in (env_remove_entries or []) if e]
                if env_remove_keys:
                    yield emit(f"Removing obsolete .env var(s): {', '.join(env_remove_keys)}")
                    try:
                        _remove_env_vars(env_remove_keys)
                    except Exception as exc:
                        yield emit(f"WARNING: Could not remove .env var(s): {exc}")

                db_script = (manifest or {}).get('db', {}).get('up')
                if db_script:
                    script_path = os.path.join(git_repo_dir, 'captive-portal', db_script)
                    yield emit(f"=== Step 2/3: Running database migration: {db_script} ===")
                    if not os.path.exists(script_path):
                        yield emit(f"ERROR: Migration script not found: {script_path}")
                        yield emit("__EXIT__:1")
                        return
                    rc = yield from stream_proc(
                        ['/bin/bash', script_path],
                        cwd=os.path.join(git_repo_dir, 'captive-portal'),
                    )
                    if rc != 0:
                        yield emit(f"ERROR: Migration {db_script} failed — aborting.")
                        yield emit("__EXIT__:1")
                        return
                    yield emit("")
                else:
                    yield emit("=== Step 2/3: No database migration needed ===")
                    yield emit("")

            elif action == 'rollback':
                changed_dirs    = status.get('back_dirs', [])
                current_hash    = status.get('current_full')
                current_short   = status.get('current_short')
                current_subject = status.get('current_subject')
                if not status.get('prev_full'):
                    yield emit("ERROR: Already on the first commit — cannot roll back.")
                    yield emit("__EXIT__:1")
                    return

                manifest  = _load_commit_manifest(current_hash, status.get('prev_full'))
                db_script = (manifest or {}).get('db', {}).get('down')
                if db_script:
                    script_path = os.path.join(git_repo_dir, 'captive-portal', db_script)
                    yield emit(f"=== Step 1/3: Running rollback migration: {db_script} ===")
                    if not os.path.exists(script_path):
                        yield emit(f"ERROR: Migration script not found: {script_path}")
                        yield emit("__EXIT__:1")
                        return
                    rc = yield from stream_proc(
                        ['/bin/bash', script_path],
                        cwd=os.path.join(git_repo_dir, 'captive-portal'),
                    )
                    if rc != 0:
                        yield emit(f"ERROR: Rollback migration {db_script} failed — aborting.")
                        yield emit("__EXIT__:1")
                        return
                    yield emit("")
                else:
                    yield emit("=== Step 1/3: No database rollback migration needed ===")
                    yield emit("")

                yield emit(f"=== Step 2/3: Rolling back from {current_short} ===")
                rc = yield from stream_proc(['git', '-C', git_repo_dir, 'checkout', '-f', 'HEAD^'])
                if rc != 0:
                    yield emit("ERROR: git checkout HEAD^ failed — aborting.")
                    yield emit("__EXIT__:1")
                    return

                env_added = [e['key'] for e in (manifest or {}).get('env', {}).get('add', []) if e.get('key')]
                if env_added:
                    yield emit(f"Removing .env var(s) added by rolled-back commit: {', '.join(env_added)}")
                    try:
                        _remove_env_vars(env_added)
                    except Exception as exc:
                        yield emit(f"WARNING: Could not remove .env var(s): {exc}")
                yield emit("")

            elif action == 'update-latest':
                commits_ahead    = status.get('commits_ahead', [])
                all_changed_dirs = status.get('latest_dirs', [])
                latest_hash      = status.get('latest_full')
                if not commits_ahead or not latest_hash:
                    yield emit("ERROR: No commits ahead — nothing to update.")
                    yield emit("__EXIT__:1")
                    return

                def _rk(entries):
                    return [e['key'] if isinstance(e, dict) else e for e in (entries or []) if e]

                total_commits = len(commits_ahead)
                for i, commit in enumerate(commits_ahead):
                    step           = i + 1
                    commit_hash    = commit['full']
                    commit_short   = commit['short']
                    commit_subject = commit['subject']
                    from_full      = commit['from_full']

                    yield emit(f"=== Commit {step}/{total_commits}: {commit_short} — {commit_subject} ===")
                    rc = yield from stream_proc(['git', '-C', git_repo_dir, 'checkout', '-f', commit_hash])
                    if rc != 0:
                        yield emit("ERROR: git checkout failed — aborting.")
                        yield emit("__EXIT__:1")
                        return
                    yield emit("")

                    step_manifest = _load_commit_manifest(commit_hash, from_full)
                    rm_keys = _rk((step_manifest or {}).get('env', {}).get('remove', []))
                    if rm_keys:
                        yield emit(f"  Removing .env var(s): {', '.join(rm_keys)}")
                        try:
                            _remove_env_vars(rm_keys)
                        except Exception as exc:
                            yield emit(f"  WARNING: Could not remove .env var(s): {exc}")

                    db_script = (step_manifest or {}).get('db', {}).get('up')
                    if db_script:
                        sp = os.path.join(git_repo_dir, 'captive-portal', db_script)
                        yield emit(f"  DB migration: {db_script}")
                        if not os.path.exists(sp):
                            yield emit(f"ERROR: Migration script not found: {sp}")
                            yield emit("__EXIT__:1")
                            return
                        rc = yield from stream_proc(
                            ['/bin/bash', sp],
                            cwd=os.path.join(git_repo_dir, 'captive-portal'),
                        )
                        if rc != 0:
                            yield emit(f"ERROR: Migration {db_script} failed — aborting.")
                            yield emit("__EXIT__:1")
                            return
                    else:
                        yield emit("  No DB migration for this commit.")
                    yield emit("")

                if all_changed_dirs:
                    yield emit(f"=== Restarting affected stacks: {', '.join(all_changed_dirs)} ===")
                    rc = yield from stream_proc(
                        ['/bin/bash', '/scripts/firmware-manager.sh', 'restart-dirs'] + all_changed_dirs,
                        env=script_env,
                    )
                    if rc != 0:
                        yield emit("ERROR: Stack restart failed.")
                        yield emit("__EXIT__:1")
                        return
                else:
                    yield emit("=== No containers to restart ===")

                yield emit("")
                yield emit("=" * 50)
                yield emit(f"UPDATE TO LATEST COMPLETE — now at {latest_hash[:7]}")
                session['firmware_last_op'] = 'update'
                session.modified = True
                yield emit("__EXIT__:0")
                return

            # Step 3 — restart affected stacks (update / rollback)
            changed_dirs = changed_dirs if 'changed_dirs' in dir() else []
            if changed_dirs:
                yield emit(f"=== Step 3/3: Restarting affected stacks: {', '.join(changed_dirs)} ===")
                rc = yield from stream_proc(
                    ['/bin/bash', '/scripts/firmware-manager.sh', 'restart-dirs'] + changed_dirs,
                    env=script_env,
                )
                if rc != 0:
                    yield emit("ERROR: Stack restart failed.")
                    yield emit("__EXIT__:1")
                    return
            else:
                yield emit("=== Step 3/3: No containers to restart ===")

            op = "UPDATE" if action == 'update' else "ROLLBACK"
            yield emit("")
            yield emit("=" * 50)
            yield emit(f"{op} COMPLETE")
            session['firmware_last_op'] = action
            session.modified = True
            yield emit("__EXIT__:0")

        except Exception as exc:
            yield emit(f"ERROR: {exc}")
            yield emit("__EXIT__:1")

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


@firmware_bp.route('/firmware/mark-done/<action>', methods=['POST'])
@login_required
@permission_required('manage_firmware')
def mark_done(action):
    if action in ('update', 'rollback', 'update-latest'):
        session['firmware_last_op'] = 'update' if action == 'update-latest' else action
        session.modified = True
    return jsonify({'ok': True})


@firmware_bp.route('/firmware/verify-last')
@login_required
@permission_required('manage_firmware')
def verify_last():
    if os.getenv('FIRMWARE_TEST_ENABLED', '').lower() in ('', '0', 'false', 'no'):
        return jsonify({'ok': False, 'error': 'Test mode not enabled'}), 403

    last_op = session.get('firmware_last_op')
    if not last_op:
        return jsonify({'ok': False, 'error': 'No operation recorded in session.'})

    status_result = _run_firmware_script('status')
    if status_result.returncode != 0:
        return jsonify({'ok': False, 'error': 'Could not read git status.'})
    status = json.loads(status_result.stdout)

    checks      = []
    manifest    = None
    current_env = _read_env_file()

    if last_op == 'update':
        manifest = _load_commit_manifest(status.get('current_full'), status.get('prev_full'))
        if manifest:
            for chk in (manifest.get('db') or {}).get('verify_up', []):
                checks.append(_run_db_verify_check(chk))
            for entry in (manifest.get('env') or {}).get('add', []):
                key     = entry['key']
                value   = current_env.get(key, '').strip()
                present = bool(value)
                required = entry.get('required', False)
                if present:
                    display = '(set)' if entry.get('sensitive') else repr(value[:40])
                    detail  = f'Present: {display}'
                    passed  = True
                elif required:
                    detail = 'MISSING — required env var not set'
                    passed = False
                else:
                    detail = 'Not set (optional — has default)'
                    passed = True
                checks.append({'category': 'env', 'name': key,
                               'description': entry.get('description', ''),
                               'pass': passed, 'detail': detail})
            for entry in (manifest.get('env') or {}).get('remove', []):
                key    = entry['key'] if isinstance(entry, dict) else entry
                if not key:
                    continue
                absent = key not in current_env
                desc   = entry.get('description', '') if isinstance(entry, dict) else ''
                checks.append({'category': 'env', 'name': key, 'description': desc,
                               'pass': absent,
                               'detail': 'Absent ✓' if absent else 'Still present ✗'})
    else:  # rollback
        manifest = _load_commit_manifest(status.get('next_full'), status.get('current_full'))
        if manifest:
            for chk in (manifest.get('db') or {}).get('verify_down', []):
                checks.append(_run_db_verify_check(chk))
            for entry in (manifest.get('env') or {}).get('add', []):
                key    = entry['key'] if isinstance(entry, dict) else entry
                if not key:
                    continue
                absent = key not in current_env
                desc   = entry.get('description', '') if isinstance(entry, dict) else ''
                checks.append({'category': 'env', 'name': key, 'description': desc,
                               'pass': absent,
                               'detail': 'Absent ✓' if absent else 'Still present ✗'})
            for entry in (manifest.get('env') or {}).get('remove', []):
                key     = entry['key'] if isinstance(entry, dict) else entry
                if not key:
                    continue
                present = key in current_env
                checks.append({'category': 'env', 'name': key,
                               'description': 'Should be restored by rollback preflight form',
                               'pass': present,
                               'detail': 'Present ✓' if present else 'MISSING ✗'})

    overall_ok = all(c['pass'] for c in checks)
    return jsonify({
        'ok':          overall_ok,
        'has_manifest': manifest is not None,
        'last_op':     last_op,
        'checks':      checks,
    })