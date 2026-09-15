"""`kyber sandbox ...` — safe room + door for any terminal AI agent."""
from __future__ import annotations

import subprocess

import typer

from kyber.sandbox import backends, local, policies, shell
from kyber.sandbox.shell import SandboxError

sandbox_app = typer.Typer(help="Safe sandbox: run any terminal AI agent isolated from your host.")

BACKEND_HELP = "Backend: auto (docker if a daemon answers), docker, or local (opt-in unsafe, no daemon)."
UNSAFE_HELP = "Acknowledge the local backend is NOT container-isolated (required for --backend local runs)."


@sandbox_app.command("up")
def up(
    name: str = typer.Option("demo", help="Sandbox session name"),
    backend: str = typer.Option("auto", help=BACKEND_HELP),
    allow_unsafe: bool = typer.Option(False, help=UNSAFE_HELP),
    image: str = typer.Option(policies.SANDBOX_IMAGE, help="Sandbox image tag (docker backend)"),
    offline: bool = typer.Option(False, help="No network inside the sandbox"),
    memory: str = typer.Option("1g", help="Container memory limit (docker backend)"),
    cpus: float = typer.Option(1.0, help="Container CPU limit (docker backend)"),
    build: bool = typer.Option(False, help="Build the sandbox image first (docker backend)"),
):
    """Create and start an isolated sandbox."""
    try:
        if backend.strip().lower() == "local" and allow_unsafe:
            typer.echo(local.UNSAFE_WARNING)
        if build:
            typer.echo(f"Building {image} ...")
            shell.build_image(tag=image)
            typer.echo("Build done.")
        info = backends.up(name, backend=backend, image=image, offline=offline,
                           memory=memory, cpus=cpus, allow_unsafe=allow_unsafe)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if info.backend == "docker":
        typer.echo(f"Sandbox {info.name!r} up (container {info.container}, network {info.network}).")
        typer.echo(f"Enter it: kyber sandbox shell {info.name}")
    else:
        typer.echo(f"Local sandbox {info.name!r} up at {info.volume} (NOT container-isolated).")
        typer.echo(f"Enter it: kyber sandbox shell --backend local --allow-unsafe {info.name}")
    typer.echo("Inside, install your agent e.g.: npm i -g opencode && opencode")


@sandbox_app.command("shell")
def shell_cmd(
    name: str = typer.Argument("demo", help="Sandbox session name"),
    backend: str = typer.Option("auto", help=BACKEND_HELP),
    allow_unsafe: bool = typer.Option(False, help=UNSAFE_HELP),
):
    """Open an interactive shell inside the sandbox (TTY)."""
    try:
        target, argv, cwd, env = backends.interactive(name, backend, allow_unsafe)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if target == "docker":
        typer.echo(f"Entering sandbox {name!r} (exit to leave; nothing touches the host except /work).")
    else:
        typer.echo(local.UNSAFE_WARNING)
        typer.echo(f"Entering LOCAL sandbox {name!r} (runs as your user; exit to leave).")
    try:
        subprocess.run(argv, cwd=cwd, env=env, check=False)
    except OSError as e:
        typer.echo(f"Error: could not spawn shell ({e})")
        raise typer.Exit(1)


@sandbox_app.command("exec")
def exec_cmd(
    name: str = typer.Argument("demo", help="Sandbox session name"),
    cmd: str = typer.Option(..., "--cmd", "-c", help="Command to run inside the sandbox"),
    backend: str = typer.Option("auto", help=BACKEND_HELP),
    allow_unsafe: bool = typer.Option(False, help=UNSAFE_HELP),
    timeout: int = typer.Option(60, help="Timeout in seconds"),
):
    """Run one command inside the sandbox (non-interactive)."""
    try:
        code, out = backends.exec_cmd(name, cmd, backend=backend,
                                      timeout=timeout, allow_unsafe=allow_unsafe)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if out:
        typer.echo(out, nl=False)
        if not out.endswith("\n"):
            typer.echo("")
    raise typer.Exit(code)


@sandbox_app.command("ls")
def ls_cmd(
    backend: str = typer.Option("auto", help="Which sessions to list: auto, docker, or local"),
):
    """List sandbox sessions."""
    try:
        sessions = backends.list_all(backend)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if not sessions:
        typer.echo("No sandboxes. Create one: kyber sandbox up --name demo")
        return
    for s in sessions:
        typer.echo(f"{s.name} [{s.status}] ({s.backend}) container={s.container} volume={s.volume}")


@sandbox_app.command("logs")
def logs_cmd(
    name: str = typer.Argument("demo"),
    backend: str = typer.Option("auto", help=BACKEND_HELP),
    tail: int = typer.Option(100),
):
    """Show sandbox container logs (docker) or audit entries (local)."""
    try:
        typer.echo(backends.logs(name, backend=backend, tail=tail), nl=False)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)


@sandbox_app.command("snapshot")
def snapshot_cmd(
    name: str = typer.Argument("demo"),
    output: str = typer.Option(..., "-o", "--output", help="Host path for the .tar of /work"),
    backend: str = typer.Option("auto", help=BACKEND_HELP),
):
    """Export /work from the sandbox to a tar file on the host."""
    try:
        path = backends.snapshot(name, output, backend=backend)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    typer.echo(f"Saved to {path}")


@sandbox_app.command("down")
def down_cmd(
    name: str = typer.Argument("demo"),
    backend: str = typer.Option("auto", help=BACKEND_HELP),
    delete_workspace: bool = typer.Option(False, help="Also delete the workspace volume"),
):
    """Destroy a sandbox (container + network, or local session; workspace kept by default)."""
    try:
        typer.echo(backends.down(name, backend=backend, keep_volume=not delete_workspace))
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)


@sandbox_app.command("build")
def build_cmd(
    tag: str = typer.Option(policies.SANDBOX_IMAGE, help="Image tag to build"),
    dockerfile: str = typer.Option("sandbox/images/Dockerfile.sandbox-agent"),
):
    """Build the sandbox image (needs a running Docker daemon)."""
    try:
        typer.echo(f"Building {tag} from {dockerfile} ...")
        shell.build_image(dockerfile=dockerfile, tag=tag)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    typer.echo(f"Built {tag}.")
