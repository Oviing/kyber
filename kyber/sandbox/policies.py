"""Sandbox security policies: single source of truth for isolation guarantees."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

BLOCKED_EGRESS_CIDRS = ["169.254.169.254/32", "169.254.170.2/32"]  # cloud metadata
ALLOWLIST_PROXY_DOMAINS: list[str] = []  # empty = no egress for untrusted code

# Destructive / out-of-scope patterns the exploiter must NEVER emit.
# Checked case-insensitively against every sandbox exec (deterministic agents
# and LLM-driven `sandbox_exec` alike). SSRF probes go through the structured
# run_probe path, so raw cloud-metadata fetches are blocked here.
FORBIDDEN_PAYLOADS = [
    "rm -rf /",
    "mkfs",
    ":(){:|:&};:",
    "shutdown",
    "drop table",
    "delete from",
    "169.254.169.254",
    "169.254.170.2",
    "metadata.google.internal",
    "nc -e",
    "/dev/tcp/",
    "chmod -r 777 /",
    "dd if=",
    "| sh",
    "| bash",
]

MAX_SNIPPET_BYTES = 1_000_000
MAX_FINDING_EVIDENCE_CHARS = 2000


@dataclass(frozen=True)
class SandboxLimits:
    memory: str = "1g"
    cpus: float = 1.0
    pids_limit: int = 128
    readonly_rootfs: bool = True
    cap_drop_all: bool = True
    no_new_privileges: bool = True
    user: str = "65532"  # non-root


DEFAULT_LIMITS = SandboxLimits()


def container_kwargs(image: str, name: str, network: Optional[str], limits: SandboxLimits) -> dict:
    kwargs: dict = {
        "image": image,
        "name": name,
        "detach": True,
        "user": limits.user,
        "mem_limit": limits.memory,
        "nano_cpus": int(limits.cpus * 1_000_000_000),
        "pids_limit": limits.pids_limit,
        "read_only": limits.readonly_rootfs,
        "cap_drop": ["ALL"] if limits.cap_drop_all else [],
        "security_opt": ["no-new-privileges"] if limits.no_new_privileges else [],
        "network": network,
    }
    return kwargs


def is_payload_allowed(cmd: str) -> bool:
    low = cmd.lower()
    return not any(p in low for p in FORBIDDEN_PAYLOADS)
