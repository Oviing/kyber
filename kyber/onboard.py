"""Onboarding helpers: environment checks for the sandbox-first CLI.

All checks are best-effort and never raise — they return structured
(ok, detail) results for display.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

from kyber.sandbox import policies

SANDBOX_IMAGE = policies.SANDBOX_IMAGE


def home_dir() -> str:
    d = os.environ.get("KYBER_HOME") or os.path.join(os.path.expanduser("~"), ".kyber")
    os.makedirs(d, exist_ok=True)
    return d


def seen_file() -> str:
    return os.path.join(home_dir(), "seen")


def is_first_run() -> bool:
    try:
        return not os.path.exists(seen_file())
    except OSError:
        return False


def mark_seen() -> None:
    try:
        with open(seen_file(), "w") as fh:
            fh.write("1")
    except OSError:
        pass


def first_run_banner() -> Optional[str]:
    if not is_first_run():
        return None
    mark_seen()
    return ("First time here? Run `kyber sandbox up --name demo`, then "
            "`kyber sandbox shell demo` — or `kyber doctor` to check setup.")


def docker_found() -> bool:
    return shutil.which("docker") is not None


def sandbox_image_status(timeout: int = 10) -> tuple[Optional[bool], str]:
    """Check the general sandbox image exists. None when docker is absent."""
    if not docker_found():
        return None, "docker not found"
    try:
        out = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as e:
        return None, f"docker query failed ({e})"
    if out.returncode != 0:
        return None, "docker query failed"
    have = set((out.stdout or "").split())
    if SANDBOX_IMAGE in have:
        return True, f"sandbox image present ({SANDBOX_IMAGE})"
    return False, f"missing sandbox image ({SANDBOX_IMAGE})"


def passthrough_keys_present(env: Optional[dict] = None) -> list[str]:
    src = env if env is not None else os.environ
    return [k for k in policies.PASSTHROUGH_ENV_KEYS if src.get(k)]
