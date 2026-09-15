"""Local helpers: home dir + docker detection.

The old managed API server is gone (full pivot to local sandbox-first);
this module keeps the small filesystem helpers the CLI still needs.
"""
from __future__ import annotations

import os
import shutil


def home_dir() -> str:
    d = os.environ.get("KYBER_HOME") or os.path.join(os.path.expanduser("~"), ".kyber")
    os.makedirs(d, exist_ok=True)
    return d


def log_file() -> str:
    return os.path.join(home_dir(), "sandbox-audit.log")


def docker_available() -> bool:
    return shutil.which("docker") is not None
