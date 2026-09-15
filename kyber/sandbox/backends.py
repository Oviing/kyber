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
       build: bool = False, mount: Optional[str] = None,
       tools: Optional[list] = None, tool_auth=None,
       subscription: bool = False) -> SandboxInfo:
    """Create a sandbox, optionally with tool flavors (`tools`) and their
    consented auth (`tool_auth`, a tools.ResolvedAuth).

    With `tools`, the docker image becomes the deterministic flavor tag
    (missing flavor → build hint); `subscription` strips ANTHROPIC_API_KEY
    so plan billing wins over per-token billing.
    """
    from kyber.sandbox import policies as policies_mod
    from kyber.sandbox import tools as tools_mod

    tool_ids = list(tools or [])
    if not valid_name(name):
        raise SandboxError(
            f"invalid sandbox name {name!r}: use letters/digits/_/- (max 64, start alnum)")
    target = resolve(backend, name)
    if tool_ids and image not in (None, shell.SANDBOX_IMAGE):
        raise SandboxError("--with and an explicit --image conflict: flavors pick "
                           "their own image tag")
    auth = tool_auth if tool_auth is not None else (
        tools_mod.resolve_auth(tool_ids) if tool_ids else None)
    if tool_ids:
        for m in (tools_mod.load_manifest(i) for i in tool_ids):
            if not tools_mod.is_consented(m):
                raise SandboxError(
                    f"tool {m.id!r} needs consent first: "
                    f"`kyber sandbox consent` to review, then retry with --yes")
    if target == "docker":
        if local.session_exists(name):
            raise SandboxError(f"sandbox {name!r} already exists in the local backend "
                               f"(kyber sandbox shell --backend local {name})")
        img = image or shell.SANDBOX_IMAGE
        if tool_ids:
            img = tools_mod.flavor_tag(tool_ids, img)
            if not shell.image_present(img):
                raise SandboxError(
                    f"flavor image {img} missing — build it first: "
                    f"`kyber sandbox build --with {','.join(tool_ids)}`")
        if build:
            shell.build_image(tag=image or shell.SANDBOX_IMAGE)
        manifest_keys = tuple(k for i in tool_ids
                              for k in tools_mod.load_manifest(i).auth_env)
        full_env = dict(policies_mod.passthrough_env(extra_keys=manifest_keys))
        if env:
            full_env.update(env)
        if auth:
            full_env.update(auth.env)
        if subscription:
            full_env.pop("ANTHROPIC_API_KEY", None)
        mounts = [dict(m) for m in (auth.mounts if auth else [])]
        info = shell.up(name, image=img,
                        offline=offline, memory=memory, cpus=cpus, env=full_env,
                        host_mount=mount,
                        extra_mounts=[{k: m[k] for k in ("src", "dest", "mode")}
                                      for m in mounts])
        if tool_ids:
            from kyber.sandbox.common import audit as _audit

            _audit("tools", f"{name} tools={','.join(tool_ids)} "
                            f"mounts={len(mounts)} subscription={subscription}")
        return info
    if mount:
        raise SandboxError("--mount is a docker-backend option; the local backend "
                           "already works on host directories (its workspace IS one)")
    if tool_ids and image not in (None, shell.SANDBOX_IMAGE):
        raise SandboxError("--with and an explicit --image conflict")
    if _docker_has(name):
        raise SandboxError(f"sandbox {name!r} already exists in the docker backend "
                           f"(kyber sandbox shell --backend docker {name})")
    auth_keys = sorted({k for i in tool_ids
                        for k in tools_mod.load_manifest(i).auth_env}) if tool_ids else []
    return local.up(name, offline=offline, allow_unsafe=allow_unsafe, env=env,
                    auth_keys=auth_keys, subscription=subscription)


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
