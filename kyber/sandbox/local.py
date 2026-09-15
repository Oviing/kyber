"""Opt-in UNSAFE local fallback: no containers, no daemon required.

Safety contract (read this before using):

* This is NOT a security boundary. It runs agent commands as YOUR user on
  YOUR machine, jailed only by cwd + scrubbed env + best-effort OS limits.
* It protects against *accidents* (wrong-dir writes, stray env secrets), not
  against a capable agent trying to escape.
* Every use requires ``allow_unsafe=True`` (CLI: ``--allow-unsafe``) plus a
  printed warning. Refuses to run as root. ``offline=True`` is enforced via
  macOS ``sandbox-exec`` when available — and REFUSED when it is not, rather
  than silently pretending.

Sessions live in ``~/.kyber/sandboxes.json``; workspaces in
``~/.kyber/workspaces/<name>/``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import time
from typing import Optional

from kyber.sandbox import policies
from kyber.sandbox.common import SandboxError, SandboxInfo, audit, home_dir, valid_name

STORE_FILENAME = "sandboxes.json"
EXEC_LOG = ".kyber-exec.log"
UNSAFE_WARNING = (
    "WARNING: local backend is NOT container-isolated — commands run as your "
    "user on this machine (cwd + env jail only). Use only for agents you trust, "
    "never as a malware boundary. Prefer Docker (`colima start`) for real isolation."
)

SEATBELT_DENY_NETWORK = "(version 1)(deny network*)"


def _store_path() -> str:
    return os.path.join(home_dir(), STORE_FILENAME)


def _load_store() -> dict:
    try:
        with open(_store_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_store(store: dict) -> None:
    try:
        with open(_store_path(), "w", encoding="utf-8") as fh:
            json.dump(store, fh, indent=2)
    except OSError as e:
        raise SandboxError(f"could not persist local session store: {e}") from e


def workspace_dir(name: str) -> str:
    base = os.path.join(home_dir(), "workspaces")
    path = os.path.abspath(os.path.join(base, name))
    if path != os.path.join(base, os.path.basename(name)) or ".." in name.split(os.sep):
        raise SandboxError(f"invalid sandbox name {name!r}")
    return path


def session_exists(name: str) -> bool:
    return name in _load_store()


def require_unsafe(allow_unsafe: bool) -> None:
    if not allow_unsafe:
        raise SandboxError(
            "local backend is not container-isolated. Retry with --allow-unsafe "
            "to acknowledge the risk (see `kyber sandbox up --help`).")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SandboxError("refusing to run the unsafe local backend as root")


def _check_name(name: str) -> None:
    if not valid_name(name):
        raise SandboxError(
            f"invalid sandbox name {name!r}: use letters/digits/_/- (max 64, start alnum)")
    if os.path.abspath(os.path.expanduser(name)) == os.path.expanduser("~"):
        raise SandboxError("refusing to use $HOME as a workspace")


def scrubbed_env(extra: Optional[dict] = None) -> dict:
    """Fresh minimal env: PATH + passthrough agent keys only. Nothing else leaks."""
    host_path = os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin")
    env = {
        "PATH": host_path,
        "TERM": os.environ.get("TERM", "xterm-256color"),
    }
    env.update(policies.passthrough_env())
    if extra:
        env.update(extra)
    return env


def _seatbelt_available() -> bool:
    return shutil.which("sandbox-exec") is not None


def seatbelt_usable(timeout: int = 10) -> bool:
    """Can `sandbox-exec` actually enforce a profile here?

    Newer macOS releases neuter sandbox-exec (even allow-all profiles fail
    with EPERM), so presence on PATH proves nothing — probe it.
    """
    if not _seatbelt_available():
        return False
    try:
        proc = subprocess.run(["sandbox-exec", "-p", "(version 1)", "/bin/true"],
                              capture_output=True, timeout=timeout, check=False)
    except Exception:
        return False
    return proc.returncode == 0


def _require_offline_enforceable() -> None:
    if _seatbelt_available() and seatbelt_usable():
        return
    raise SandboxError(
        "offline cannot be enforced locally on this machine (`sandbox-exec` "
        "missing or non-functional). Use the docker backend for enforced "
        "offline (`colima start`), or recreate without --offline.")


def up(name: str, offline: bool = False, allow_unsafe: bool = False,
       env: Optional[dict] = None) -> SandboxInfo:
    """Create a local workspace session."""
    require_unsafe(allow_unsafe)
    _check_name(name)
    if offline:
        # Fail fast: an "offline" session that cannot block the network would lie.
        _require_offline_enforceable()
    store = _load_store()
    if name in store:
        raise SandboxError(f"sandbox {name!r} already exists (kyber sandbox shell {name})")
    ws = workspace_dir(name)
    try:
        os.makedirs(ws, exist_ok=True)
    except OSError as e:
        raise SandboxError(f"could not create workspace {ws}: {e}") from e
    store[name] = {"backend": "local", "workspace": ws, "offline": offline,
                   "offline_enforced": offline,  # True only if seatbelt probe passed at up
                   "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
    _save_store(store)
    audit("local-up", f"{name} workspace={ws} offline={offline}")
    return SandboxInfo(name=name, container=f"local:{name}",
                       network="local:offline" if offline else "local:shared",
                       volume=ws, image="local-process", status="ready", backend="local")


def _session(name: str) -> dict:
    _check_name(name)
    store = _load_store()
    rec = store.get(name)
    if not rec or rec.get("backend") != "local":
        raise SandboxError(f"local sandbox {name!r} not found "
                           f"(kyber sandbox up --backend local --allow-unsafe --name {name})")
    return rec


def _limit_resources(timeout: int):
    """preexec_fn: cap CPU seconds. Best-effort, POSIX only."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (timeout + 30, timeout + 60))
    except Exception:
        pass


def exec_cmd(name: str, cmd: str, timeout: int = 60,
             allow_unsafe: bool = False) -> tuple[int, str]:
    """Run a command in the workspace with scrubbed env. Returns (code, output)."""
    require_unsafe(allow_unsafe)
    if not (cmd or "").strip():
        raise SandboxError("empty command")
    rec = _session(name)
    ws = rec["workspace"]
    if not os.path.isdir(ws):
        raise SandboxError(f"workspace for {name!r} is gone ({ws})")
    offline = bool(rec.get("offline"))
    argv: list[str]
    if offline:
        if not rec.get("offline_enforced") or not seatbelt_usable():
            raise SandboxError(
                "offline cannot be enforced locally on this machine (`sandbox-exec` "
                "missing or non-functional). Use the docker backend for enforced "
                "offline, or recreate without --offline.")
        argv = ["sandbox-exec", "-p", SEATBELT_DENY_NETWORK, "/bin/sh", "-c", cmd]
    else:
        argv = ["/bin/sh", "-c", cmd]
    audit("local-exec", f"{name} {cmd[:200]}")
    try:
        proc = subprocess.run(argv, cwd=ws, env={**scrubbed_env(), "HOME": ws},
                              capture_output=True, text=True, timeout=timeout,
                              preexec_fn=lambda: _limit_resources(timeout), check=False)
    except subprocess.TimeoutExpired:
        line = f"\n[kyber] timed out after {timeout}s (code 124)\n"
        _append_exec_log(ws, cmd, line)
        return 124, line
    except OSError as e:
        raise SandboxError(f"local exec failed: {e}") from e
    out = ((proc.stdout or "") + (proc.stderr or ""))[-20000:]
    _append_exec_log(ws, cmd, out)
    return proc.returncode, out


def _append_exec_log(ws: str, cmd: str, out: str) -> None:
    try:
        with open(os.path.join(ws, EXEC_LOG), "a", encoding="utf-8") as fh:
            fh.write(f"$ {cmd[:500]}\n{out[-4000:]}\n")
    except OSError:
        pass


def interactive_spec(name: str, allow_unsafe: bool = False) -> tuple[list[str], str, dict]:
    """(argv, cwd, env) for the CLI to spawn an interactive shell in the workspace."""
    require_unsafe(allow_unsafe)
    rec = _session(name)
    ws = rec["workspace"]
    shell_bin = os.environ.get("SHELL", "/bin/bash")
    if not os.path.exists(shell_bin):
        shell_bin = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
    return [shell_bin, "-i"], ws, {**scrubbed_env(), "HOME": ws}


def logs(name: str, tail: int = 100) -> str:
    rec = _session(name)
    _ = rec
    lines: list[str] = []
    try:
        with open(os.path.join(home_dir(), "sandbox-audit.log"), encoding="utf-8") as fh:
            for line in fh:
                if f" {name} " in line or f" {name}(" in line or line.strip().endswith(f" {name}") or f"local-exec {name} " in line or f"local-up {name} " in line:
                    lines.append(line)
    except OSError:
        pass
    if not lines:
        return f"no audit entries for local sandbox {name!r} yet"
    return "".join(lines[-tail:])[-20000:]


def list_sessions() -> list[SandboxInfo]:
    store = _load_store()
    out: list[SandboxInfo] = []
    for sname in sorted(store):
        rec = store[sname]
        if rec.get("backend") != "local":
            continue
        ws = rec.get("workspace", "")
        out.append(SandboxInfo(
            name=sname, container=f"local:{sname}",
            network="local:offline" if rec.get("offline") else "local:shared",
            volume=ws, image="local-process",
            status="ready" if os.path.isdir(ws) else "workspace-missing",
            backend="local"))
    return out


def snapshot(name: str, output_path: str) -> str:
    rec = _session(name)
    ws = rec["workspace"]
    if not os.path.isdir(ws):
        raise SandboxError(f"workspace for {name!r} is gone ({ws})")
    abs_path = os.path.abspath(os.path.expanduser(output_path))
    try:
        with tarfile.open(abs_path, "w") as tf:
            tf.add(ws, arcname="work")
    except OSError as e:
        raise SandboxError(f"could not write {abs_path}: {e}") from e
    audit("local-snapshot", f"{name} -> {abs_path}")
    return abs_path


def down(name: str, keep_volume: bool = True) -> str:
    rec = _session(name)
    store = _load_store()
    store.pop(name, None)
    _save_store(store)
    if not keep_volume:
        try:
            shutil.rmtree(rec["workspace"])
        except OSError:
            pass
    audit("local-down", f"{name} keep_volume={keep_volume}")
    return (f"sandbox {name!r} destroyed"
            + (" (workspace kept)" if keep_volume else " (workspace deleted)"))
