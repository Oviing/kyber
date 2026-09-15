"""Shared sandbox primitives: errors, session info, home/audit helpers.

Container-specific (docker) and process-specific (local) backends both build
on these so naming, validation, and audit trails stay consistent.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass

LABEL = "kyber.sandbox"
CONTAINER_PREFIX = "kyber-sb-"
AUDIT_FILENAME = "sandbox-audit.log"


class SandboxError(RuntimeError):
    pass


def valid_name(name: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name or ""))


def home_dir() -> str:
    d = os.environ.get("KYBER_HOME") or os.path.join(os.path.expanduser("~"), ".kyber")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def audit(action: str, detail: str = "") -> None:
    try:
        with open(os.path.join(home_dir(), AUDIT_FILENAME), "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {action} {detail[:300]}\n")
    except OSError:
        pass


@dataclass
class SandboxInfo:
    name: str
    container: str
    network: str
    volume: str
    image: str
    status: str = "running"
    backend: str = "docker"
