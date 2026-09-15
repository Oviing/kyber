"""`kyber sandbox ...` — safe room + door for any terminal AI agent."""
from __future__ import annotations

import subprocess

import typer
from rich.console import Console
from rich.panel import Panel

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
    mount: str = typer.Option("", help="Host dir to bind as /work (docker backend; "
                               "agent can touch exactly this dir, host tools see it live)"),
    with_tools: str = typer.Option("", "--with", help="Comma-separated tool flavors baked in "
                                    "(e.g. --with claude,codex): no reinstall, "
                                    "auth forwarded with consent"),
    yes: bool = typer.Option(False, help="Grant tool auth consent without asking"),
    subscription: bool = typer.Option(False, help="Strip ANTHROPIC_API_KEY from the "
                                         "sandbox so subscription billing always wins"),
):
    """Create and start an isolated sandbox."""
    from kyber.sandbox import tools as tools_mod

    try:
        tool_ids = tools_mod.parse_id_list(with_tools)
        auth = tools_mod.resolve_auth(tool_ids) if tool_ids else None
        conflict = tools_mod.subscription_conflict()
        if conflict and tool_ids and not subscription:
            typer.echo(f"WARNING: {conflict}")
        if auth:
            for gap in auth.missing:
                typer.echo(f"Note: {gap} (tool may still work, or log in on host first)")
        for tool_id in tool_ids:
            manifest = tools_mod.load_manifest(tool_id)
            if not tools_mod.is_consented(manifest):
                typer.echo(tools_mod.consent_report(tool_id))
                granted = yes or typer.confirm(
                    f"Forward {manifest.display} auth into the sandbox?",
                    default=False)
                if not granted:
                    typer.echo("Aborted (consent required for tool auth).")
                    raise typer.Exit(1)
                tools_mod.grant_consent(manifest)
        if backend.strip().lower() == "local" and allow_unsafe:
            typer.echo(local.UNSAFE_WARNING)
        if build:
            typer.echo(f"Building {image} ...")
            shell.build_image(tag=image)
            typer.echo("Build done.")
        info = backends.up(name, backend=backend, image=image, offline=offline,
                           memory=memory, cpus=cpus, allow_unsafe=allow_unsafe,
                           mount=mount or None, tools=tool_ids or None,
                           tool_auth=auth, subscription=subscription)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if info.backend == "docker":
        work = f"host mount {info.volume}" if (mount or None) else f"volume {info.volume}"
        extras = f" tools={','.join(tool_ids)}" if tool_ids else ""
        typer.echo(f"Sandbox {info.name!r} up (container {info.container}, {work}{extras}).")
        typer.echo(f"Enter it: kyber sandbox shell {info.name}")
    else:
        typer.echo(f"Local sandbox {info.name!r} up at {info.volume} (NOT container-isolated).")
        typer.echo(f"Enter it: kyber sandbox shell --backend local --allow-unsafe {info.name}")
    if tool_ids:
        typer.echo("Tools baked in: {} (auth forwarded, no reinstall/login)".format(
            ", ".join(tool_ids)))
    else:
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
    console = Console()
    if target == "docker":
        console.print(Panel(
            f"Entering sandbox [bold]{name}[/bold] — isolated container.\n"
            "Nothing touches the host except /work. [bold]exit[/bold] to leave.",
            title="⬢ kyber sandbox", border_style="magenta"))
    else:
        console.print(Panel(
            f"Entering [bold]LOCAL[/bold] sandbox [bold]{name}[/bold] — "
            "runs as your user, NOT container-isolated.",
            title="⚠ kyber local", border_style="red"))
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
    with_tools: str = typer.Option("", "--with", help="Bake tool flavors in (e.g. --with "
                                    "claude,codex); flavor gets its own tag"),
):
    """Build the sandbox image (needs a running Docker daemon)."""
    from kyber.sandbox import tools as tools_mod

    try:
        tool_ids = tools_mod.parse_id_list(with_tools)
        if tool_ids:
            unknown = [i for i in tool_ids if i not in tools_mod.available_ids()]
            if unknown:
                raise SandboxError(
                    f"unknown tool(s): {', '.join(unknown)}. "
                    f"Available: {', '.join(tools_mod.available_ids())}")
            typer.echo(f"Baking tools into flavor: {', '.join(tool_ids)} ...")
            built = shell.build_image(dockerfile=dockerfile,
                                      tag=None if tag == policies.SANDBOX_IMAGE else tag,
                                      with_tools=tool_ids)
        else:
            typer.echo(f"Building {tag} from {dockerfile} ...")
            built = shell.build_image(dockerfile=dockerfile, tag=tag)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    typer.echo(f"Built {built}.")


@sandbox_app.command("tools")
def tools_cmd():
    """List agent tool flavors (built-in + ~/.kyber/tools.d)."""
    from kyber.sandbox import tools as tools_mod

    try:
        manifests = tools_mod.list_manifests()
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    if not manifests:
        typer.echo("No tool manifests. Company tools live in ~/.kyber/tools.d/<id>.yaml")
        return
    for m in manifests:
        auth_bits = ([f"env:{k}" for k in m.auth_env]
                     + [f"file:{f.src}->[{f.mode}]" for f in m.auth_files])
        typer.echo(f"{m.id} [{m.source}] — {m.display}: {m.description}")
        typer.echo("   auth: {} | check: {}".format(
            ", ".join(auth_bits) or "none", m.check))


@sandbox_app.command("consent")
def consent_cmd(revoke: str = typer.Option("", help="Revoke consent for a tool id")):
    """Review or revoke tool-auth consent grants."""
    from kyber.sandbox import tools as tools_mod

    if revoke:
        if tools_mod.revoke_consent(revoke.strip().lower()):
            typer.echo(f"Consent revoked for {revoke.strip().lower()!r}.")
        else:
            typer.echo(f"No consent grant for {revoke.strip().lower()!r}.")
        return
    try:
        manifests = tools_mod.list_manifests()
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    for m in manifests:
        state = "granted" if tools_mod.is_consented(m) else "pending"
        typer.echo(f"{m.id}: {state}")


@sandbox_app.command("view")
def view_cmd(
    name: str = typer.Argument("demo", help="Sandbox session name"),
    backend: str = typer.Option("auto", help=BACKEND_HELP),
    interval: float = typer.Option(2.0, help="Refresh interval in seconds (live mode)"),
    once: bool = typer.Option(False, "--once", help="Print one static snapshot and exit"),
):
    """Live read-only dashboard for a sandbox (Ctrl-C to quit)."""
    from kyber.sandbox import view as view_mod

    try:
        view_mod.run(name, backend=backend, interval=interval, once=once)
    except SandboxError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        pass
