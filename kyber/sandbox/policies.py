"""Sandbox security policies: single source of truth for isolation guarantees.

Two modes:

* ``strict`` (legacy red-team default): read-only rootfs, every exec gated
  by ``FORBIDDEN_PAYLOADS``. Kept for backward compatibility.
* ``open`` (general agent sandbox): the terminal agent inside may run
  ANYTHING (install packages, rm -rf, curl, ...). Safety comes from the
  *container boundary*, never from command censorship:

  - no ``docker.sock`` mount, ever
  - ``cap_drop: ALL``, ``no-new-privileges``, non-root user
  - ``pids_limit`` + memory/cpu caps
  - per-session bridge network, destroyed with the container
  - /work maps to exactly one source: a dedicated named volume, or one
    explicit host dir via `up --mount` (validated: never $HOME, /, or ~/.kyber)
  - ``tmpfs`` on ``/tmp`` so the rootfs can stay writable without host writes
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

BLOCKED_EGRESS_CIDRS = ["169.254.169.254/32", "169.254.170.2/32"]  # cloud metadata
ALLOWLIST_PROXY_DOMAINS: list[str] = []  # empty = no egress for untrusted code (strict mode)

# Destructive / out-of-scope patterns. Only enforced in ``strict`` mode
# (legacy red-team scans). In ``open`` mode the agent is explicitly allowed
# to run these *inside* the container.
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

# General sandbox defaults.
SANDBOX_IMAGE = "kyber-sandbox:latest"
SANDBOX_WORKDIR = "/work"
SANDBOX_TMPFS = {"/tmp": "size=256m,mode=1777"}

# Env var carrying the session name into the container (colors the prompt,
# tab title, and entry banner via the baked ~/.bashrc identity layer).
SANDBOX_NAME_VAR = "KYBER_SANDBOX_NAME"
# Image label marking builds that contain the identity layer (`kyber.identity=1`).
IDENTITY_LABEL = "kyber.identity"

# Host env vars passed through into the sandbox so the user can run their
# own terminal agent (opencode / claude / codex / ...) with their own keys.
# Values are read from the host at `up` time; never written to disk.
# CLAUDE_CODE_OAUTH_TOKEN is the `claude setup-token` output: it lets a Pro/Max
# subscription work inside the sandbox with no API key and no browser login.
PASSTHROUGH_ENV_KEYS = (
    "LLM_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "KYBER_LLM_MODEL",
    "LLM_MODEL",
)

# Moto for `kyber sandbox shell`.
SANDBOX_MOTD = (
    "Kyber sandbox — isolated container. You can do anything in here; "
    "nothing touches the host except /work (workspace volume). "
    "`exit` to leave; `kyber sandbox down <name>` destroys the container."
)


@dataclass(frozen=True)
class SandboxLimits:
    memory: str = "1g"
    cpus: float = 1.0
    pids_limit: int = 128
    readonly_rootfs: bool = True
    cap_drop_all: bool = True
    no_new_privileges: bool = True
    user: str = "65532"  # non-root


DEFAULT_LIMITS = SandboxLimits()  # strict legacy default

# Open-mode default: writable rootfs (+ tmpfs on /tmp) so the agent can
# install tools; all other hardening stays on.
OPEN_LIMITS = SandboxLimits(readonly_rootfs=False)


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
    # Writable-rootfs containers still get a size-capped tmpfs on /tmp so
    # throwaway writes never touch the host or the image layer unboundedly.
    if not limits.readonly_rootfs:
        kwargs["tmpfs"] = dict(SANDBOX_TMPFS)
    return kwargs


def sandbox_container_kwargs(
    name: str,
    network: Optional[str] = None,
    image: str = SANDBOX_IMAGE,
    limits: SandboxLimits = OPEN_LIMITS,
    workspace_volume: Optional[str] = None,
    host_mount: Optional[str] = None,
    env: Optional[dict] = None,
) -> dict:
    """kwargs for a general agent sandbox container.

    Never mounts docker.sock. /work maps to exactly one source: either the
    dedicated named workspace volume or one explicit host dir (``--mount``).
    """
    kwargs = container_kwargs(image, name, network, limits)
    kwargs.update(
        {
            "tty": True,
            "stdin_open": True,
            "working_dir": SANDBOX_WORKDIR,
            "command": "sleep 3600",
            "privileged": False,
        }
    )
    if host_mount:
        kwargs["volumes"] = {host_mount: {"bind": SANDBOX_WORKDIR, "mode": "rw"}}
    elif workspace_volume:
        kwargs["volumes"] = {workspace_volume: {"bind": SANDBOX_WORKDIR, "mode": "rw"}}
    if env:
        kwargs["environment"] = dict(env)
    return kwargs


def passthrough_env(host_env: Optional[dict] = None,
                    extra_keys: tuple = ()) -> dict:
    """Subset of host env safe to inject into the sandbox.

    `extra_keys` opens the gate for tool-manifest auth vars (e.g. company
    providers) — but only for keys the caller explicitly names, never wholesale.
    """
    import os

    src = host_env if host_env is not None else os.environ
    allowed = tuple(PASSTHROUGH_ENV_KEYS) + tuple(extra_keys or ())
    return {k: src[k] for k in allowed if src.get(k)}


def is_payload_allowed(cmd: str, mode: str = "strict") -> bool:
    """In ``open`` mode every payload is allowed inside the container."""
    if mode == "open":
        return True
    low = (cmd or "").lower()
    return not any(p in low for p in FORBIDDEN_PAYLOADS)
