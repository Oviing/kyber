"""Managed local API server for the CLI: health checks, autostart, PID tracking.

Safety rule: the CLI only ever stops a server it started itself (tracked via
a PID file). A port occupied by anything else is reported, never killed.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

START_TIMEOUT_S = 20.0


class ServerError(RuntimeError):
    pass


def home_dir() -> str:
    d = os.environ.get("KYBER_HOME") or os.path.join(os.path.expanduser("~"), ".kyber")
    os.makedirs(d, exist_ok=True)
    return d


def pid_file() -> str:
    return os.path.join(home_dir(), "kyber.pid")


def log_file() -> str:
    return os.path.join(home_dir(), "api.log")


def local_port_from_api(api: str) -> Optional[int]:
    """Port if the API URL is local, else None (never autostart remote hosts)."""
    try:
        parts = urlparse(api if "://" in api else f"http://{api}")
    except Exception:
        return None
    if (parts.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
        return None
    return parts.port or 8000


def is_healthy(api: str, timeout: float = 3.0) -> bool:
    try:
        r = httpx.get(api.rstrip("/") + "/health", timeout=timeout)
        return r.status_code == 200 and r.json().get("ok") is True
    except Exception:
        return False


def port_in_use(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def _pid_is_ours(pid: int) -> bool:
    """Best-effort check that a PID is a kyber/uvicorn server (/proc only)."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmd = fh.read().decode(errors="replace")
        return "kyber" in cmd or "uvicorn" in cmd
    except OSError:
        return True  # no /proc (e.g. macOS): trust the PID file


def read_pid() -> Optional[int]:
    try:
        with open(pid_file()) as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    return pid if _pid_is_ours(pid) else None


def write_pid(pid: int) -> None:
    with open(pid_file(), "w") as fh:
        fh.write(str(pid))


def clear_pid() -> None:
    try:
        os.remove(pid_file())
    except OSError:
        pass


def start_server(port: int, foreground: bool = False):
    """Launch uvicorn. Foreground blocks; background records a PID file."""
    cmd = [sys.executable, "-m", "uvicorn", "kyber.api.main:app", "--port", str(port)]
    if foreground:
        subprocess.run(cmd, check=False)
        return None
    with open(log_file(), "a") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        write_pid(proc.pid)
    return proc


def wait_for_health(api: str, timeout: float = START_TIMEOUT_S) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_healthy(api, timeout=2.0):
            return True
        time.sleep(0.5)
    return False


def ensure_api_up(api: str, autostart: bool = True) -> str:
    """Make sure the API is reachable. Returns 'reused' or 'started'.

    Raises ServerError with an actionable message instead of tracebacks.
    """
    if is_healthy(api):
        return "reused"
    pid = read_pid()
    if pid is not None:
        if wait_for_health(api, timeout=10.0):
            return "reused"
        raise ServerError(
            f"managed server (pid {pid}) is not responding. Run `kyber down`, "
            f"then retry. Log: {log_file()}")
    port = local_port_from_api(api)
    if port is None:
        raise ServerError(
            f"API at {api} is unreachable and is not local. Start it there first, "
            "then retry with --api.")
    if not autostart:
        raise ServerError(
            f"API at {api} is unreachable. Run `kyber up --port {port}` first.")
    if port_in_use(port):
        raise ServerError(
            f"port {port} is occupied by another process (not a healthy Kyber API). "
            "Free it, or use a different --port/--api.")
    start_server(port)
    if not wait_for_health(api):
        raise ServerError(f"server started but never became healthy. Log: {log_file()}")
    return "started"


def stop_server() -> str:
    """Stop only the server we started. Never touches foreign processes."""
    pid = read_pid()
    if pid is None:
        clear_pid()
        return "no managed server running"
    import signal

    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.25)
            try:
                os.kill(pid, 0)
            except OSError:
                break
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    clear_pid()
    return f"stopped server (pid {pid})"


def docker_available() -> bool:
    return shutil.which("docker") is not None
