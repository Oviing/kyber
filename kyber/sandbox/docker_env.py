"""Single source of truth for container-runtime detection.

The CLI being on PATH is NOT the same as a working daemon — on macOS the
typical failure is Docker Desktop / Colima installed but not running, so the
socket in ``DOCKER_HOST`` (or the default) answers nothing. Every check here
is best-effort and never raises; callers get ``(state, detail)`` tuples with
an actionable fix hint.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

DEFAULT_SOCKET_MACOS = os.path.expanduser("~/.docker/run/docker.sock")
DEFAULT_SOCKET_LINUX = "/var/run/docker.sock"


def cli_found() -> bool:
    return shutil.which("docker") is not None


def socket_hint() -> str:
    """Which socket / host we would try, for error messages."""
    explicit = os.environ.get("DOCKER_HOST", "")
    if explicit:
        return explicit
    import sys

    if sys.platform == "darwin":
        return f"unix://{DEFAULT_SOCKET_MACOS}"
    return f"unix://{DEFAULT_SOCKET_LINUX}"


def _ping_via_python(timeout: int = 5) -> Optional[bool]:
    """True/False via docker-py, None when the package is missing."""
    try:
        import docker
    except ImportError:
        return None
    try:
        client = docker.from_env(timeout=timeout)
        client.ping()
        return True
    except Exception:
        return False


def daemon_reachable(timeout: int = 5) -> tuple[bool, str]:
    """Is a Docker daemon reachable right now?

    Returns (True, detail) or (False, detail-with-fix-hint). The detail tail
    always contains the underlying error so `docker query failed` vagueness
    is gone.
    """
    if not cli_found():
        return False, ("docker CLI not found on PATH. Install Docker Desktop "
                       "(macOS/Windows) or docker-ce + colima (macOS: `brew install "
                       "colima docker && colima start`).")
    py = _ping_via_python(timeout=timeout)
    if py is True:
        return True, "docker daemon reachable"
    last_err = ""
    if py is False:
        last_err = " (docker-py ping failed)"
    # Fallback / second opinion via the CLI itself (also covers podman-compat).
    try:
        out = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                             capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as e:
        return False, (f"docker daemon unreachable at {socket_hint()}{last_err}: {e}. "
                       "Start it (macOS: `open -a Docker` or `colima start`), then retry.")
    if out.returncode == 0:
        return True, f"docker daemon reachable (server {(out.stdout or '').strip()})"
    tail = ((out.stderr or out.stdout) or "").strip().splitlines()[-5:]
    hint = ("Start it (macOS: `open -a Docker` or `colima start`), then retry. "
            "No daemon at all? Kyber has an opt-in container-free fallback "
            "(`kyber sandbox up --backend local --allow-unsafe --name <name>`).")
    joined = " ".join(t.strip() for t in tail if t.strip())
    return False, (f"docker daemon unreachable at {socket_hint()}: {joined[:400]}. {hint}")
