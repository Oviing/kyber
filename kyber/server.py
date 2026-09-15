"""Local helpers: home dir + docker detection.

The old managed API server is gone (full pivot to local sandbox-first);
this module keeps the small filesystem helpers the CLI still needs.
Runtime detection lives in kyber.sandbox.docker_env (CLI-present vs
daemon-reachable are different states); the functions here stay as
thin backward-compatible wrappers.
"""
from __future__ import annotations

import os

from kyber.sandbox import docker_env


def home_dir() -> str:
    d = os.environ.get("KYBER_HOME") or os.path.join(os.path.expanduser("~"), ".kyber")
    os.makedirs(d, exist_ok=True)
    return d


def log_file() -> str:
    return os.path.join(home_dir(), "sandbox-audit.log")


def docker_available() -> bool:
    """Docker CLI on PATH (does NOT imply the daemon is up)."""
    return docker_env.cli_found()


def daemon_reachable(timeout: int = 5) -> tuple[bool, str]:
    return docker_env.daemon_reachable(timeout=timeout)
