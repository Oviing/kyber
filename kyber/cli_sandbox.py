"""`kyber sandbox ...` — safe room + door for any terminal AI agent."""
from __future__ import annotations

import subprocess

import typer

from kyber.sandbox import policies, shell
from kyber.sandbox.shell import SandboxError

sandbox_app = typer.Typer(help="Safe sandbox: run any terminal AI agent isolated from your host.")


@sandbox_app.command("up")
def up(
    name: str = typer.Option("demo", help="Sandbox session name"),
    image: str = typer.Option(policies.SANDBOX_IMAGE, help="Sandbox image tag"),
    offline: bool = typer.Option(False, help="No network inside the sandbox"),
    memory: str = typer.Option("1g", help="Container memory limit"),
    cpus: float = typer.Option(1.0, help="Container CPU limit"),
    build: bool = typer.Option(False, help="Build the sandbox image first"),
):
    """Create and start an isolated sandbox container."""
    try:
        if build:
            typer.echo(f"Building {image} ...")
            shell.build_image(tag=image)
            typer.echo("Build done.")
        info = shell.up(name, image=image, offline=offline, memory=memory, cpus=cpus)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    typer.echo(f"Sandbox {info.name!r} up (container {info.container}, network {info.network}).")
    typer.echo(f"Enter it: kyber sandbox shell {info.name}")
    typer.echo("Inside, install your agent e.g.: npm i -g opencode && opencode")


@sandbox_app.command("shell")
def shell_cmd(name: str = typer.Argument("demo", help="Sandbox session name")):
    """Open an interactive shell inside the sandbox (TTY)."""
    try:
        argv = shell.shell_argv(name)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if not shell.docker_available():
        typer.echo("Error: docker not found — install Docker first.")
        raise typer.Exit(1)
    typer.echo(f"Entering sandbox {name!r} (exit to leave; nothing touches the host except /work).")
    try:
        subprocess.run(argv, check=False)
    except OSError as e:
        typer.echo(f"Error: could not exec docker ({e})")
        raise typer.Exit(1)


@sandbox_app.command("exec")
def exec_cmd(
    name: str = typer.Argument("demo", help="Sandbox session name"),
    cmd: str = typer.Option(..., "--", help="Command to run inside the sandbox"),
    timeout: int = typer.Option(60, help="Timeout in seconds"),
):
    """Run one command inside the sandbox (non-interactive)."""
    try:
        code, out = shell.exec_cmd(name, cmd, timeout=timeout)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if out:
        typer.echo(out, nl=False)
        if not out.endswith("\n"):
            typer.echo("")
    raise typer.Exit(code)


@sandbox_app.command("ls")
def ls_cmd():
    """List sandbox sessions."""
    try:
        sessions = shell.list_sessions()
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if not sessions:
        typer.echo("No sandboxes. Create one: kyber sandbox up --name demo")
        return
    for s in sessions:
        typer.echo(f"{s.name} [{s.status}] container={s.container} volume={s.volume}")


@sandbox_app.command("logs")
def logs_cmd(
    name: str = typer.Argument("demo"),
    tail: int = typer.Option(100),
):
    """Show sandbox container logs."""
    try:
        typer.echo(shell.logs(name, tail=tail), nl=False)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)


@sandbox_app.command("snapshot")
def snapshot_cmd(
    name: str = typer.Argument("demo"),
    output: str = typer.Option(..., "-o", "--output", help="Host path for the .tar of /work"),
):
    """Export /work from the sandbox to a tar file on the host."""
    try:
        path = shell.snapshot(name, output)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    typer.echo(f"Saved to {path}")


@sandbox_app.command("down")
def down_cmd(
    name: str = typer.Argument("demo"),
    delete_workspace: bool = typer.Option(False, help="Also delete the workspace volume"),
):
    """Destroy a sandbox (container + network; workspace kept by default)."""
    try:
        typer.echo(shell.down(name, keep_volume=not delete_workspace))
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)


@sandbox_app.command("build")
def build_cmd(
    tag: str = typer.Option(policies.SANDBOX_IMAGE, help="Image tag to build"),
    dockerfile: str = typer.Option("sandbox/images/Dockerfile.sandbox-agent"),
):
    """Build the sandbox image."""
    try:
        typer.echo(f"Building {tag} from {dockerfile} ...")
        shell.build_image(dockerfile=dockerfile, tag=tag)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    typer.echo(f"Built {tag}.")
