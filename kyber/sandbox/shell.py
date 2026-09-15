"""General agent sandbox runtime: safe room + door, no opinions about the agent.

Kyber provisions, hardens, and destroys the container. Inside, the user runs
whatever terminal AI agent they like (opencode, claude, codex, aider, ...).
In ``open`` mode NOTHING the agent runs inside the container is censored —
safety comes from the container boundary (see policies.py):

- cap_drop ALL, no-new-privileges, non-root, pids/memory/cpu caps
- no docker.sock mount, ever
- no host bind-mounts except one dedicated workspace volume at /work
- per-session bridge network (``--offline`` makes it internal), destroyed on down
- every host-initiated action is appended to an audit log (best-effort)
"""
from __future__ import annotations

import os
import re
import shutil
import time
from dataclasses import dataclass
from typing import Optional

from kyber.sandbox import policies
from kyber.sandbox.policies import OPEN_LIMITS, SANDBOX_IMAGE

LABEL = "kyber.sandbox"
CONTAINER_PREFIX = "kyber-sb-"
AUDIT_FILENAME = "sandbox-audit.log"


class SandboxError(RuntimeError):
    pass


def valid_name(name: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name or ""))


def _home_dir() -> str:
    d = os.environ.get("KYBER_HOME") or os.path.join(os.path.expanduser("~"), ".kyber")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def _audit(action: str, detail: str = "") -> None:
    try:
        with open(os.path.join(_home_dir(), AUDIT_FILENAME), "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {action} {detail[:300]}\n")
    except OSError:
        pass


def docker_available() -> bool:
    return shutil.which("docker") is not None


def container_name(name: str) -> str:
    return f"{CONTAINER_PREFIX}{name}"


def network_name(name: str) -> str:
    return f"{CONTAINER_PREFIX}{name}-net"


def volume_name(name: str) -> str:
    return f"kyber-ws-{name}"


def _docker(client=None):
    if client is not None:
        return client
    if not docker_available():
        raise SandboxError("docker not found — install Docker to use the sandbox")
    try:
        import docker
    except ImportError as e:
        raise SandboxError("docker python package missing (pip install docker)") from e
    try:
        return docker.from_env()
    except Exception as e:
        raise SandboxError(f"cannot reach docker daemon: {e}") from e


@dataclass
class SandboxInfo:
    name: str
    container: str
    network: str
    volume: str
    image: str
    status: str = "running"


def up(
    name: str,
    image: str = SANDBOX_IMAGE,
    offline: bool = False,
    memory: str = OPEN_LIMITS.memory,
    cpus: float = OPEN_LIMITS.cpus,
    keep_volume: bool = True,  # kept for symmetry with down(); volumes persist by default
    env: Optional[dict] = None,
    client=None,
) -> SandboxInfo:
    """Create network + workspace volume + hardened container. Idempotent-ish.

    Raises SandboxError with an actionable message (never a traceback).
    Full egress by default; ``offline=True`` creates an internal network.
    """
    _ = keep_volume
    if not valid_name(name):
        raise SandboxError(
            f"invalid sandbox name {name!r}: use letters/digits/_/- (max 64, start alnum)")
    limits = policies.SandboxLimits(
        memory=memory, cpus=cpus, pids_limit=OPEN_LIMITS.pids_limit, readonly_rootfs=False)
    cname, nname, vname = container_name(name), network_name(name), volume_name(name)
    dc = _docker(client)

    if env is None:
        env = policies.passthrough_env()

    # Bail early with a clear message if the session already exists.
    try:
        dc.containers.get(cname)
        raise SandboxError(f"sandbox {name!r} already exists (kyber sandbox shell {name})")
    except SandboxError:
        raise
    except Exception:
        pass

    try:
        dc.networks.create(nname, driver="bridge", internal=offline,
                           labels={LABEL: name})
    except Exception as e:
        raise SandboxError(f"could not create network: {e}") from e
    try:
        try:
            dc.volumes.get(vname)
        except Exception:
            dc.volumes.create(vname, labels={LABEL: name})
        kwargs = policies.sandbox_container_kwargs(
            cname, nname, image=image, limits=limits,
            workspace_volume=vname, env=env)
        kwargs["labels"] = {LABEL: name}
        dc.containers.run(**kwargs)
    except Exception as e:
        down(name, client=dc)
        raise SandboxError(f"sandbox up failed: {e}") from e
    _audit("up", f"{name} image={image} offline={offline}")
    return SandboxInfo(name=name, container=cname, network=nname, volume=vname, image=image)


def exec_cmd(name: str, cmd: str, timeout: int = 60, client=None) -> tuple[int, str]:
    """Run a command inside the sandbox. No censorship (open mode)."""
    if not valid_name(name):
        raise SandboxError(f"invalid sandbox name {name!r}")
    if not (cmd or "").strip():
        raise SandboxError("empty command")
    dc = _docker(client)
    try:
        container = dc.containers.get(container_name(name))
    except Exception as e:
        raise SandboxError(f"sandbox {name!r} not found (kyber sandbox up --name {name})") from e
    _audit("exec", f"{name} {cmd[:200]}")
    try:
        result = container.exec_run(cmd, demux=False)
        code, out = result.exit_code, result.output
    except Exception as e:
        raise SandboxError(f"exec failed: {e}") from e
    text = out.decode("utf-8", errors="replace") if isinstance(out, (bytes, bytearray)) else str(out)
    return code, text[:20000]


def shell_argv(name: str) -> list[str]:
    """`docker exec -it` argv for an interactive shell (TTY passthrough)."""
    if not valid_name(name):
        raise SandboxError(f"invalid sandbox name {name!r}")
    motd = policies.SANDBOX_MOTD.replace("'", "'\"'\"'")
    return ["docker", "exec", "-it", container_name(name),
            "bash", "-c", f"echo '{motd}' && exec bash"]


def logs(name: str, tail: int = 100, client=None) -> str:
    dc = _docker(client)
    try:
        container = dc.containers.get(container_name(name))
    except Exception as e:
        raise SandboxError(f"sandbox {name!r} not found") from e
    try:
        out = container.logs(tail=tail)
    except Exception as e:
        raise SandboxError(f"could not read logs: {e}") from e
    if isinstance(out, (bytes, bytearray)):
        return out.decode("utf-8", errors="replace")[-20000:]
    return str(out)[-20000:]


def list_sessions(client=None) -> list[SandboxInfo]:
    dc = _docker(client)
    found: list[SandboxInfo] = []
    try:
        containers = dc.containers.list(all=True, filters={"label": LABEL})
    except Exception as e:
        raise SandboxError(f"could not list sandboxes: {e}") from e
    for c in containers:
        labels = getattr(c, "labels", None) or {}
        if isinstance(getattr(c, "attrs", None), dict):
            labels = c.attrs.get("Config", {}).get("Labels", {}) or labels
        sname = labels.get(LABEL, "") if isinstance(labels, dict) else ""
        cname = getattr(c, "name", "") or ""
        if not sname and cname.startswith(CONTAINER_PREFIX):
            sname = cname[len(CONTAINER_PREFIX):]
        if not sname:
            continue
        try:
            status = c.status  # type: ignore[attr-defined]
        except Exception:
            status = "unknown"
        if isinstance(status, str) and callable(getattr(c, "status", None)):
            status = "unknown"
        found.append(SandboxInfo(name=sname, container=cname,
                                 network=network_name(sname), volume=volume_name(sname),
                                 image=",".join(getattr(c, "image", None) and
                                                getattr(c.image, "tags", []) or []),
                                 status=str(status)))
    return sorted(found, key=lambda s: s.name)


def snapshot(name: str, output_path: str, client=None) -> str:
    """Export /work from the sandbox as a .tar.gz on the host."""
    if not valid_name(name):
        raise SandboxError(f"invalid sandbox name {name!r}")
    dc = _docker(client)
    try:
        container = dc.containers.get(container_name(name))
    except Exception as e:
        raise SandboxError(f"sandbox {name!r} not found") from e
    abs_path = os.path.abspath(os.path.expanduser(output_path))
    try:
        bits, _stat = container.get_archive("/work")
    except Exception as e:
        raise SandboxError(f"snapshot failed: {e}") from e
    try:
        with open(abs_path, "wb") as fh:
            for chunk in bits:  # noqa: FURB122 - chunks may be non-bytes from docker stream
                fh.write(chunk if isinstance(chunk, (bytes, bytearray)) else bytes(chunk))
    except OSError as e:
        raise SandboxError(f"could not write {abs_path}: {e}") from e
    _audit("snapshot", f"{name} -> {abs_path}")
    return abs_path


def down(name: str, keep_volume: bool = True, client=None) -> str:
    """Destroy container + network. Workspace volume kept by default."""
    if not valid_name(name):
        raise SandboxError(f"invalid sandbox name {name!r}")
    dc = _docker(client)
    cname, nname, vname = container_name(name), network_name(name), volume_name(name)
    try:
        container = dc.containers.get(cname)
    except Exception:
        container = None
    if container is not None:
        try:
            container.remove(force=True)
        except Exception:
            pass
    try:
        net = dc.networks.get(nname)
        net.remove()
    except Exception:
        pass
    if not keep_volume:
        try:
            vol = dc.volumes.get(vname)
            vol.remove(force=True)
        except Exception:
            pass
    _audit("down", f"{name} keep_volume={keep_volume}")
    return (f"sandbox {name!r} destroyed"
            + (" (workspace kept)" if keep_volume else " (workspace deleted)"))


def build_image(dockerfile: str = "sandbox/images/Dockerfile.sandbox-agent",
                tag: str = SANDBOX_IMAGE) -> str:
    """Build the sandbox image via `docker build`. Returns the tag."""
    if not docker_available():
        raise SandboxError("docker not found — install Docker first")
    import subprocess

    cmd = ["docker", "build", "-f", dockerfile, "-t", tag,
           os.path.dirname(dockerfile) or "."]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SandboxError(f"docker build failed:\n{(proc.stderr or proc.stdout)[-3000:]}")
    _audit("build", tag)
    return tag


def image_present(tag: str = SANDBOX_IMAGE, client=None) -> bool:
    try:
        dc = _docker(client)
    except SandboxError:
        return False
    try:
        dc.images.get(tag)
        return True
    except Exception:
        return False
