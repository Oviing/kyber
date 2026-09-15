"""Onboarding helpers: environment checks for the sandbox-first CLI.

All checks are best-effort and never raise — they return structured
(ok, detail) results for display.
"""
from __future__ import annotations

import os
import subprocess
from typing import Optional

from kyber.sandbox import docker_env, policies

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
    """Docker CLI on PATH (does NOT imply the daemon is up)."""
    return docker_env.cli_found()


def docker_daemon_status(timeout: int = 5) -> tuple[Optional[bool], str]:
    """(True, ...) daemon answers; (False, ...) CLI missing or daemon down.

    Returns None only when the check itself could not run.
    """
    if not docker_env.cli_found():
        return False, "docker CLI not found"
    try:
        ok, detail = docker_env.daemon_reachable(timeout=timeout)
    except Exception as e:
        return None, f"docker check failed ({e})"
    return ok, detail


def sandbox_image_status(timeout: int = 10) -> tuple[Optional[bool], str]:
    """Check the general sandbox image exists. Preserves the daemon error tail."""
    if not docker_env.cli_found():
        return None, "docker CLI not found"
    ok, daemon_detail = docker_daemon_status(timeout=timeout)
    if not ok:
        short = daemon_detail.split(". ")[0]
        short = short[:117] + "..." if len(short) > 120 else short
        return None, f"unknown ({short} — see daemon line)"
    try:
        out = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as e:
        return None, f"docker query failed ({e})"
    if out.returncode != 0:
        tail = ((out.stderr or out.stdout) or "").strip().splitlines()[-3:]
        joined = " ".join(t.strip() for t in tail if t.strip())[:300]
        return None, f"docker query failed: {joined}" if joined else "docker query failed"
    have = set((out.stdout or "").split())
    if SANDBOX_IMAGE in have:
        return True, f"sandbox image present ({SANDBOX_IMAGE})"
    return False, f"missing sandbox image ({SANDBOX_IMAGE})"


def passthrough_keys_present(env: Optional[dict] = None) -> list[str]:
    src = env if env is not None else os.environ
    return [k for k in policies.PASSTHROUGH_ENV_KEYS if src.get(k)]


def sandbox_identity_status(image: str = SANDBOX_IMAGE) -> tuple[Optional[bool], str]:
    """Does the sandbox image carry the terminal identity layer?

    True = branded prompt/banner present; False = image predates the layer
    (rebuild to get it); None = cannot tell (no daemon).
    """
    from kyber.sandbox import shell as shell_mod

    try:
        present = shell_mod.image_identity_present(image)
    except Exception as e:
        return None, f"identity check failed ({e})"
    if present:
        return True, "terminal identity layer present (branded prompt + banner)"
    ok, _ = docker_daemon_status()
    if not ok:
        return None, "identity layer unknown (daemon unreachable)"
    return False, "image predates the terminal identity layer — run `kyber sandbox build`"


def tool_readiness() -> list[tuple[str, str, str, str]]:
    """(tool id, auth state, consent state, detail) per known tool. Host-side only."""
    from kyber.sandbox import tools as tools_mod

    try:
        manifests = tools_mod.list_manifests()
    except Exception as e:
        return [("tools", "error", "error", str(e))]
    rows: list[tuple[str, str, str, str]] = []
    for m in manifests:
        try:
            resolved = tools_mod.resolve_auth([m.id])
        except Exception as e:
            rows.append((m.id, "error", "pending", str(e)))
            continue
        auth_state = "ready" if not resolved.missing else "missing-auth"
        consent_state = "granted" if tools_mod.is_consented(m) else "pending"
        detail = "; ".join(resolved.missing) if resolved.missing else m.display
        rows.append((m.id, auth_state, consent_state, detail))
    return rows
