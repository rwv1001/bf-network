# blueprints/admin/switch_terminal.py

import os
import pty
import signal
import select
import struct
import fcntl
import termios
import threading
import subprocess
import logging

from flask import request
from flask_login import current_user
from flask_socketio import Namespace, emit, disconnect

from core.switch import get_switch_hosts
from extensions import socketio

TERMINAL_NS = "/switch-terminal"

logger = logging.getLogger(__name__)

_terminal_sessions = {}


def build_switch_ssh_args(host: str) -> list:
    switch_user = os.getenv("SWITCH_USER", "robert")
    switch_port = os.getenv("SWITCH_SSH_PORT", "22")
    switch_key = os.getenv("SWITCH_KEY_PATH", "")

    args = [
        "ssh",
        "-tt",
        "-p", switch_port,
        "-o", "HostKeyAlgorithms=+ssh-rsa",
        "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=3",
    ]

    if switch_key:
        args.extend(["-i", switch_key])

    args.append(f"{switch_user}@{host}")
    return args


def set_pty_size(fd: int, rows: int, cols: int):
    rows = max(10, min(int(rows or 24), 200))
    cols = max(20, min(int(cols or 80), 300))
    packed = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)


def socket_user_can_manage_vlans() -> bool:
    """
    Replace this with your real permission check.

    Your HTTP route uses @permission_required('manage_vlans'), so the socket
    should enforce the same permission rather than only checking login.
    """
    if not current_user or not current_user.is_authenticated:
        return False

    # Example only. Adapt to your User / permission model.
    if hasattr(current_user, "has_permission"):
        return current_user.has_permission("manage_vlans")

    return True


class SwitchTerminalNamespace(Namespace):
    def on_connect(self):
        if not socket_user_can_manage_vlans():
            disconnect()
            return

        logger.info("Switch terminal socket connected: sid=%s user=%s",
                    request.sid, getattr(current_user, "id", None))

    def on_start(self, data):
        if not socket_user_can_manage_vlans():
            emit("terminal_error", {"message": "Not authorised."})
            disconnect()
            return

        host = (data or {}).get("host", "").strip()
        allowed_hosts = set(get_switch_hosts())

        if host not in allowed_hosts:
            emit("terminal_error", {"message": "Invalid switch host."})
            disconnect()
            return

        if request.sid in _terminal_sessions:
            emit("terminal_error", {"message": "Terminal already running."})
            return

        master_fd, slave_fd = pty.openpty()

        rows = int((data or {}).get("rows") or 24)
        cols = int((data or {}).get("cols") or 80)
        set_pty_size(master_fd, rows, cols)

        ssh_args = build_switch_ssh_args(host)

        proc = subprocess.Popen(
            ssh_args,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            start_new_session=True,
            text=False,
        )

        os.close(slave_fd)
        os.write(master_fd, b"screen-length disable\n")

        _terminal_sessions[request.sid] = {
            "host": host,
            "fd": master_fd,
            "proc": proc,
        }

        logger.warning(
            "Interactive switch terminal started: user=%s host=%s sid=%s",
            getattr(current_user, "id", None),
            host,
            request.sid,
        )

        thread = threading.Thread(
            target=self._reader_loop,
            args=(request.sid, master_fd, proc),
            daemon=True,
        )
        thread.start()

    def _reader_loop(self, sid, fd, proc):
        try:
            while proc.poll() is None:
                readable, _, _ = select.select([fd], [], [], 0.2)
                if fd not in readable:
                    continue

                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break

                if not chunk:
                    break

                socketio.emit(
                    "terminal_output",
                    {"data": chunk.decode("utf-8", errors="replace")},
                    to=sid,
                    namespace=TERMINAL_NS,
                )
        finally:
            self._cleanup(sid)
            socketio.emit("terminal_closed", {}, to=sid, namespace=TERMINAL_NS)

    def on_input(self, data):
        session = _terminal_sessions.get(request.sid)
        if not session:
            return

        text = (data or {}).get("data", "")
        if not isinstance(text, str):
            return

        os.write(session["fd"], text.encode("utf-8", errors="ignore"))

    def on_resize(self, data):
        session = _terminal_sessions.get(request.sid)
        if not session:
            return

        rows = (data or {}).get("rows", 24)
        cols = (data or {}).get("cols", 80)
        set_pty_size(session["fd"], rows, cols)

    def on_disconnect(self, reason=None):
        logger.info(
            "Switch terminal socket disconnected: sid=%s reason=%s",
            request.sid,
            reason,
        )
        self._cleanup(request.sid)

    def _cleanup(self, sid):
        session = _terminal_sessions.pop(sid, None)
        if not session:
            return
        proc = session.get("proc")
        fd = session.get("fd")
        try:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
        except Exception:
            pass
        try:
            if fd is not None:
                os.close(fd)
        except Exception:
            pass

        logger.info("Interactive switch terminal closed: host=%s sid=%s", session.get("host"), sid)