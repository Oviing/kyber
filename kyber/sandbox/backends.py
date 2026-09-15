"""Backend dispatcher: `--backend auto|docker|local` routing.

* ``docker`` — real container isolation (kyber.sandbox.shell).
* ``local`` — opt-in UNSAFE process fallback (kyber.sandbox.local).
* ``auto`` — docker when a daemon answers; otherwise a clear error that names
  the exact local-fallback retry command. Auto NEVER silently runs untrusted
  code without isolation.

Name collisions across backends are refused at ``up`` time (a `demo` in one
backend blocks `demo` in the other) so later reads are unambiguous.
"""
from __future__ import annotations

from typing import Optional

from kyber.sandbox import docker_env, local, shell
from kyber.sandbox.common import SandboxError, SandboxInfo, valid_name

BACKENDS = ("auto", "docker", "local")

NO_DAEMON_RETRY = "kyber sandbox up --backend local --allow-unsafe --name {name}"


def check_backend(value: str) -> str:
    v = (value or "auto").strip().lower()
    if v not in BACKENDS:
        raise SandboxError(f"invalid backend {value!r}: choose from {', '.join(BACKENDS)}")
    return v


def resolve(backend: str = "auto", name: str = "demo") -> str:
    """Map auto/explicit to 'docker' or 'local'. May raise SandboxError."""
    v = check_backend(backend)
    if v in ("docker", "local"):
        return v
    ok, detail = docker_env.daemon_reachable()
    if ok:
        return "docker"
    base = detail.split(" No daemon at all?")[0].rstrip()
    raise SandboxError(f"{base} — or run without containers: "
                       f"`{NO_DAEMON_RETRY.format(name=name)}`")


def _docker_has(name: str) -> bool:
    """Best-effort: does a docker container own this name? False when unknown."""
    try:
        dc = shell._docker()
    except SandboxError:
        return False
    try:
        dc.containers.get(shell.container_name(name))
        return True
    except Exception:
        return False


def up(name: str, backend: str = "auto", image: Optional[str] = None,
       offline: bool = False, memory: str = "1g", cpus: float = 1.0,
       allow_unsafe: bool = False, env: Optional[dict] = None,
       build: bool = False) -> SandboxInfo:
    if not valid_name(name):
        raise SandboxError(
            f"invalid sandbox name {name!r}: use letters/digits/_/- (max 64, start alnum)")
    target = resolve(backend, name)
    if target == "docker":
        if local.session_exists(name):
            raise SandboxError(f"sandbox {name!r} already exists in the local backend "
                               f"(kyber sandbox shell --backend local {name})")
        if build:
            shell.build_image(tag=image or shell.SANDBOX_IMAGE)
        return shell.up(name, image=image or shell.SANDBOX_IMAGE,
                        offline=offline, memory=memory, cpus=cpus, env=env)
    if _docker_has(name):
        raise SandboxError(f"sandbox {name!r} already exists in the docker backend "
                           f"(kyber sandbox shell --backend docker {name})")
    return local.up(name, offline=offline, allow_unsafe=allow_unsafe, env=env)


def exec_cmd(name: str, cmd: str, backend: str = "auto", timeout: int = 60,
             allow_unsafe: bool = False, client=None) -> tuple[int, str]:
    target = _read_backend(name, backend)
    if target == "docker":
        return shell.exec_cmd(name, cmd, timeout=timeout, client=client)
    return local.exec_cmd(name, cmd, timeout=timeout, allow_unsafe=allow_unsafe)


def interactive(name: str, backend: str = "auto",
                allow_unsafe: bool = False) -> tuple[str, list[str], Optional[str], Optional[dict]]:
    """(resolved_backend, argv, cwd, env) for the CLI to spawn."""
    target = _read_backend(name, backend)
    if target == "docker":
        return "docker", shell.shell_argv(name), None, None
    argv, cwd, env = local.interactive_spec(name, allow_unsafe=allow_unsafe)
    return "local", argv, cwd, env


def _read_backend(name: str, backend: str) -> str:
    """Which backend owns `name` for read/exec paths. May raise SandboxError."""
    v = check_backend(backend)
    if v in ("docker", "local"):
        return v
    # auto: local store is authoritative without needing a daemon.
    if local.session_exists(name):
        if _docker_has(name):
            raise SandboxError(f"sandbox {name!r} exists in BOTH backends — retry with "
                               "an explicit --backend docker|local")
        return "local"
    ok, detail = docker_env.daemon_reachable()
    if not ok:
        raise SandboxError(f"{detail} — or use the local session: "
                           f"`kyber sandbox exec --backend local {name} "
                           f"--cmd \"...\"` "
                           f"(needs --allow-unsafe when creating)")
    return "docker"


def logs(name: str, backend: str = "auto", tail: int = 100, client=None) -> str:
    target = _read_backend(name, backend)
    if target == "docker":
        return shell.logs(name, tail=tail, client=client)
    return local.logs(name, tail=tail)


def snapshot(name: str, output_path: str, backend: str = "auto", client=None) -> str:
    target = _read_backend(name, backend)
    if target == "docker":
        return shell.snapshot(name, output_path, client=client)
    return local.snapshot(name, output_path)


def down(name: str, backend: str = "auto", keep_volume: bool = True, client=None) -> str:
    target = _read_backend(name, backend)
    if target == "docker":
        return shell.down(name, keep_volume=keep_volume, client=client)
    return local.down(name, keep_volume=keep_volume)


def list_all(backend: str = "auto", client=None) -> list[SandboxInfo]:
    v = check_backend(backend)
    out: list[SandboxInfo] = []
    if v in ("auto", "docker"):
        try:
            out.extend(shell.list_sessions(client=client))
        except SandboxError:
            if v == "docker":
                raise
    if v in ("auto", "local"):
        out.extend(local.list_sessions())
    return sorted(out, key=lambda s: (s.backend, s.name))
