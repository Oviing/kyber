from __future__ import annotations

import os
import sys

import typer

from kyber.cli_sandbox import sandbox_app

app = typer.Typer(help="Kyber safe agent sandbox — run any terminal AI agent isolated from your host.",
                  no_args_is_help=False)
app.add_typer(sandbox_app, name="sandbox")


@app.command()
def init(check_only: bool = typer.Option(False, help="Only report status, change nothing"),
         yes: bool = typer.Option(False, help="Create missing files without asking")):
    """One-command setup: checks Docker, bootstraps .env, reports sandbox status."""
    from kyber import onboard

    typer.echo("Kyber setup check")
    problems: list[str] = []

    typer.echo(f"  [ok] python {sys.version.split()[0]}")

    if onboard.docker_found():
        typer.echo("  [ok] docker found")
        ok, detail = onboard.sandbox_image_status()
        if ok:
            typer.echo(f"  [ok] {detail}")
        elif ok is None:
            typer.echo(f"  [..] {detail}")
        else:
            typer.echo(f"  [..] {detail} — run `kyber sandbox build`")
    else:
        typer.echo("  [..] docker not found — install Docker to use the sandbox")

    env_path = os.path.join(os.getcwd(), ".env")
    example = os.path.join(os.getcwd(), ".env.example")
    if os.path.exists(env_path):
        typer.echo("  [ok] .env present")
    elif os.path.exists(example):
        if check_only:
            typer.echo("  [..] .env missing (would create from .env.example)")
        elif yes or typer.confirm("No .env found. Create one from .env.example?", default=True):
            try:
                with open(example, encoding="utf-8") as fh:
                    content = fh.read()
                with open(env_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                typer.echo("  [ok] created .env from .env.example")
            except OSError as e:
                problems.append(f"could not create .env ({e})")
                typer.echo(f"  [FAIL] could not create .env ({e})")
        else:
            typer.echo("  [..] skipped .env (keys can also come from your shell env)")
    else:
        typer.echo("  [..] no .env or .env.example found (shell env keys still work)")

    keys = onboard.passthrough_keys_present()
    if keys:
        typer.echo(f"  [ok] agent keys in env: {', '.join(keys)}")
    else:
        typer.echo("  [..] no agent API keys in env (set e.g. ANTHROPIC_API_KEY before `up`)")

    if problems:
        typer.echo("Setup FAILED:")
        for p in problems:
            typer.echo(f"  - {p}")
        raise typer.Exit(1)
    typer.echo("Next: `kyber sandbox up --name demo` then `kyber sandbox shell demo`.")


@app.command()
def doctor():
    """Diagnose the local sandbox setup: Docker, image, keys, home."""
    from kyber import onboard

    lines = []
    lines.append(f"python: {sys.version.split()[0]}")
    lines.append("docker: {}".format("found" if onboard.docker_found() else "not found"))
    ok, detail = onboard.sandbox_image_status()
    lines.append(f"sandbox image: {detail}")
    if ok is False:
        lines.append("  build it with: kyber sandbox build")
    keys = onboard.passthrough_keys_present()
    lines.append("agent keys: {}".format(", ".join(keys) if keys else "none in env"))
    lines.append(f"home: {onboard.home_dir()} (sessions/audit log)")
    typer.echo("\n".join(lines))


@app.callback(invoke_without_command=True)
def callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        from kyber import onboard

        banner = onboard.first_run_banner()
        if banner:
            typer.echo(banner)
        typer.echo("Kyber safe agent sandbox")
        typer.echo("  kyber sandbox up --name demo     create an isolated sandbox")
        typer.echo("  kyber sandbox shell demo         open a terminal inside it")
        typer.echo("  # inside: npm i -g opencode && opencode   (or claude/codex/aider)")
        typer.echo("  kyber sandbox down demo          destroy it (workspace kept)")
        typer.echo("More: kyber --help, kyber sandbox --help, kyber doctor.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
