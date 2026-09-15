from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Optional

import httpx
import typer

from kyber.server import (
    ServerError,
    docker_available,
    ensure_api_up,
    home_dir,
    is_healthy,
    local_port_from_api,
    log_file,
    port_in_use,
    read_pid,
    start_server,
    stop_server,
    wait_for_health,
)

MAX_SNIPPET_BYTES = 1_000_000
PROFILES = ("quick", "full", "adversarial", "agent")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

app = typer.Typer(help="Kyber red-team sandbox CLI", no_args_is_help=False)


def _client(api: str, key: str, timeout: float = 30) -> httpx.Client:
    return httpx.Client(base_url=api, headers={"X-API-Key": key}, timeout=timeout)


def looks_like_zip(path: str) -> bool:
    if path.lower().endswith(".zip"):
        return True
    try:
        with open(path, "rb") as fh:
            return fh.read(4)[:2] == b"PK"
    except OSError:
        return False


def read_text_file(path: str) -> str:
    """Read a text source file or raise a clean CLI error (no tracebacks)."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise typer.BadParameter(f"cannot read file: {e}") from e
    if size > MAX_SNIPPET_BYTES:
        raise typer.BadParameter(
            f"file too large ({size} bytes, max {MAX_SNIPPET_BYTES}); upload a .zip instead")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError as e:
        raise typer.BadParameter(
            f"{path!r} is not UTF-8 text. If it is an archive, "
            f"upload a .zip; otherwise unzip/convert to a text source file first ({e})") from e


def _do_submit(api: str, api_key: str, file: Optional[str], repo: Optional[str],
               url: Optional[str], language: str, profile: str,
               consent_owned: bool, goal: Optional[str] = None) -> dict[str, Any]:
    """Shared submit implementation. Returns the scan response dict."""
    c = _client(api, api_key)
    if file:
        if looks_like_zip(file):
            try:
                with open(file, "rb") as fh:
                    data = fh.read()
            except OSError as e:
                raise typer.BadParameter(f"cannot read file: {e}") from e
            up = _client(api, api_key, timeout=120)
            try:
                resp = up.post("/v1/targets/upload",
                               files={"file": (os.path.basename(file), data, "application/zip")},
                               data={"language": language})
            except httpx.HTTPError as e:
                raise typer.BadParameter(f"upload failed: {e}") from e
            if resp.status_code >= 400:
                raise typer.BadParameter(f"upload rejected ({resp.status_code}): {resp.text[:500]}")
            t = resp.json()
        else:
            snippet = read_text_file(file)
            t = c.post("/v1/targets",
                       json={"type": "snippet", "language": language, "snippet": snippet}).json()
    elif repo:
        t = c.post("/v1/targets", json={"type": "repo", "language": language, "repo_url": repo}).json()
    elif url:
        t = c.post("/v1/targets", json={"type": "url", "language": language, "service_url": url}).json()
    else:
        raise typer.BadParameter("provide --file, --repo, or --url")
    body: dict[str, Any] = {"target_id": t["id"], "profile": profile,
                            "consent_owned": consent_owned}
    if goal:
        body["goal"] = goal
    return c.post("/v1/scans", json=body).json()


def _wait_for_scan(client: httpx.Client, scan_id: str, rounds: int = 120) -> dict[str, Any]:
    s: dict[str, Any] = {}
    for _ in range(rounds):
        s = client.get(f"/v1/scans/{scan_id}").json()
        if s.get("status") in ("done", "failed", "timeout"):
            break
        time.sleep(3)
    return s


def _fetch_findings(client: httpx.Client, scan_id: str) -> list[dict[str, Any]]:
    return client.get(f"/v1/scans/{scan_id}/findings").json()


@app.command()
def submit(file: Optional[str] = typer.Option(None, help="Snippet file to upload"),
           repo: Optional[str] = typer.Option(None, help="Git repo URL"),
           url: Optional[str] = typer.Option(None, help="Live service URL (requires --consent-owned)"),
           language: str = typer.Option("auto"),
           profile: str = typer.Option("quick"),
           consent_owned: bool = typer.Option(False, help="Confirm you own/have permission to test the target"),
           goal: Optional[str] = typer.Option(None, help="Agent goal (profile=agent)"),
           api: str = typer.Option("http://localhost:8000"),
           api_key: str = typer.Option("dev-key-1", envvar="KYBER_API_KEY")):
    s = _do_submit(api, api_key, file, repo, url, language, profile, consent_owned, goal)
    typer.echo(json.dumps(s))
    return s["id"]


@app.command()
def status(scan_id: str, api: str = typer.Option("http://localhost:8000"),
           api_key: str = typer.Option("dev-key-1", envvar="KYBER_API_KEY")):
    c = _client(api, api_key)
    typer.echo(json.dumps(c.get(f"/v1/scans/{scan_id}").json(), indent=2))


@app.command()
def report(scan_id: str, format: str = typer.Option("json"),
           wait: bool = typer.Option(True),
           api: str = typer.Option("http://localhost:8000"),
           api_key: str = typer.Option("dev-key-1", envvar="KYBER_API_KEY")):
    c = _client(api, api_key)
    if wait:
        _wait_for_scan(c, scan_id)
    if format == "sarif":
        typer.echo(json.dumps(c.get(f"/v1/scans/{scan_id}/report.sarif").json(), indent=2))
    else:
        typer.echo(json.dumps(_fetch_findings(c, scan_id), indent=2))


@app.command()
def up(port: int = typer.Option(8000, help="Local port for the API"),
       foreground: bool = typer.Option(False, help="Run in foreground (Ctrl+C stops it)")):
    """Start the local API server (managed: stoppable with `kyber down`)."""
    api = f"http://localhost:{port}"
    if is_healthy(api):
        typer.echo(f"API already healthy at {api}")
        return
    if port_in_use(port):
        raise typer.BadParameter(
            f"port {port} is occupied by another process. Free it or use --port.")
    typer.echo(f"Starting API on {api} ...")
    start_server(port, foreground=foreground)
    if foreground:
        return
    if wait_for_health(api):
        typer.echo(f"API up at {api} (pid {read_pid()}, log {log_file()})")
    else:
        raise typer.BadParameter(f"server started but never became healthy. Log: {log_file()}")


@app.command()
def down():
    """Stop the API server started by `kyber up` (never touches other processes)."""
    typer.echo(stop_server())


@app.command()
def doctor(api: str = typer.Option("http://localhost:8000"),
           api_key: str = typer.Option("dev-key-1", envvar="KYBER_API_KEY")):
    """Diagnose the local setup: Python, API, port, storage, Docker, key."""
    lines = []
    lines.append(f"python: {sys.version.split()[0]}")
    lines.append("api {}: {}".format(api, "healthy" if is_healthy(api) else "unreachable"))
    pid = read_pid()
    lines.append("managed server: {}".format(f"running (pid {pid})" if pid else "not running"))
    port = local_port_from_api(api)
    if port is not None:
        lines.append("port {}: {}".format(
            port, "in use" if port_in_use(port) else "free"))
    try:
        from kyber.config import settings

        d = settings.artifact_dir
        os.makedirs(d, exist_ok=True)
        lines.append(f"artifact dir {d}: writable")
    except Exception as e:
        lines.append(f"artifact dir: PROBLEM ({e})")
    lines.append("docker: {}".format("available" if docker_available() else "not found (fallback scans only)"))
    lines.append("api key: {}".format(
        "from KYBER_API_KEY" if os.environ.get("KYBER_API_KEY") else "default dev key"))
    lines.append(f"home: {home_dir()} (pid/log)")
    typer.echo("\n".join(lines))


def _guess_kind(value: str) -> str:
    if os.path.exists(value):
        return "file"
    low = value.lower()
    if "github.com" in low or "gitlab.com" in low or low.endswith(".git"):
        return "repo"
    return "url"


def _prompt_kind(default: str = "file") -> str:
    while True:
        kind = typer.prompt("Scan what?", default=default).strip().lower()
        if kind in ("file", "repo", "url"):
            return kind
        typer.echo("Please answer file, repo, or url.")


def _prompt_path() -> Optional[str]:
    while True:
        p = typer.prompt("File path (empty to abort)", default="").strip()
        if not p:
            return None
        if not os.path.exists(p):
            typer.echo(f"No such file: {p}")
            continue
        if os.path.isdir(p):
            typer.echo("Single files or .zip archives only, not directories.")
            continue
        return p


def _prompt_profile(default: str = "quick") -> str:
    while True:
        p = typer.prompt("Profile?", default=default).strip().lower()
        if p in PROFILES:
            return p
        typer.echo("Please answer one of: {}.".format(", ".join(PROFILES)))


def _print_summary(scan_id: str, findings: list[dict[str, Any]]) -> None:
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "?"))
        counts[sev] = counts.get(sev, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: SEVERITY_RANK.get(kv[0], 99))
    typer.echo("Scan {} done: {} finding(s) [{}]".format(
        scan_id, len(findings),
        ", ".join(f"{v} {k}" for k, v in ordered) or "none"))
    if not findings:
        typer.echo("Hint: 0 findings can mean a clean target — or an unscannable one "
                   "(e.g. binary-only .zip with no source/text files). "
                   "Check for an info/no-scannable-text finding in the full report.")
    top = sorted(findings, key=lambda f: SEVERITY_RANK.get(str(f.get("severity", "?")), 99))[:5]
    for f in top:
        typer.echo("[{}] {} — {} ({})".format(
            f.get("severity"), f.get("rule_id"), f.get("title"), f.get("location")))


def _prompt_save_path(scan_id: str) -> Optional[str]:
    """Ask whether to save, then where. Never treats 'yes' as a filename."""
    if not typer.confirm("Save full report to a file?", default=False):
        return None
    default = f"report-{scan_id}.json"
    out = typer.prompt("Report path", default=default).strip() or default
    # Guard against a bare yes/no answer landing in the path prompt.
    if out.lower() in ("yes", "y", "no", "n"):
        out = default
    return out


def _save_findings(path: str, findings: list[dict[str, Any]]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        typer.echo(f"Saved to {path}")
    except OSError as e:
        typer.echo(f"Could not save: {e}")


def run_wizard(api: str, api_key: str, target: Optional[str] = None,
               profile: Optional[str] = None, consent_owned: bool = False) -> None:
    """Guided flow: ensure API is up, ask what to scan, run it, show findings."""
    typer.echo("Kyber red-team sandbox — guided scan")
    try:
        state = ensure_api_up(api)
    except ServerError as e:
        typer.echo(f"Cannot reach API: {e}")
        raise typer.Exit(1)
    started_here = state == "started"
    typer.echo("API started." if started_here else "API ready (already running).")

    kind: Optional[str] = None
    value: Optional[str] = None
    if target:
        if os.path.exists(target):
            kind, value = "file", target
        else:
            kind = _guess_kind(target)
            value = target if kind != "file" else None
    if kind is None:
        kind = _prompt_kind()
    if kind == "file":
        if value is None:
            value = _prompt_path()
            if value is None:
                typer.echo("Aborted.")
                return
    elif kind == "repo":
        if value is None:
            value = typer.prompt("Repo URL", default="").strip()
        if not value:
            typer.echo("Aborted.")
            return
    else:
        if value is None:
            value = typer.prompt("Service URL", default="").strip()
        if not value:
            typer.echo("Aborted.")
            return
        if not consent_owned:
            consent_owned = typer.confirm(
                "Do you own this target / have permission to test it?", default=False)
        if not consent_owned:
            typer.echo("Aborted (consent is required for live targets).")
            return

    if profile is None:
        profile = _prompt_profile()
    elif profile not in PROFILES:
        typer.echo("Invalid profile {!r}; choose from {}.".format(profile, ", ".join(PROFILES)))
        raise typer.Exit(1)

    try:
        if kind == "file":
            s = _do_submit(api, api_key, value, None, None, "auto", profile, False)
        elif kind == "repo":
            s = _do_submit(api, api_key, None, value, None, "auto", profile, False)
        else:
            s = _do_submit(api, api_key, None, None, value, "auto", profile, True)
    except typer.BadParameter as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    scan_id = s["id"]
    c = _client(api, api_key)
    final = _wait_for_scan(c, scan_id)
    if final.get("status") != "done":
        typer.echo("Scan {} ended with status: {} ({})".format(
            scan_id, final.get("status"), final.get("error") or "no detail"))
        raise typer.Exit(1)
    findings = _fetch_findings(c, scan_id)
    _print_summary(scan_id, findings)

    out = _prompt_save_path(scan_id)
    if out:
        _save_findings(out, findings)
    typer.echo(f"Fetch later with: kyber report {scan_id}")
    if started_here:
        typer.echo("Stop the API with: kyber down")


@app.command()
def wizard(api: str = typer.Option("http://localhost:8000"),
           api_key: str = typer.Option("dev-key-1", envvar="KYBER_API_KEY"),
           target: Optional[str] = typer.Option(None, help="File path, repo URL, or service URL"),
           profile: Optional[str] = typer.Option(None, help="quick, full, adversarial, or agent"),
           consent_owned: bool = typer.Option(False, help="Permission to test a live URL target")):
    """Guided scan: sets up the API if needed, asks what to scan, shows findings."""
    run_wizard(api, api_key, target, profile, consent_owned)


@app.command()
def agent(target: Optional[str] = typer.Option(None, help="File path, repo URL, or service URL"),
          goal: Optional[str] = typer.Option(None, help="What should the agent try to find/do?"),
          profile: str = typer.Option("agent", help="Scan profile (agent runs the LLM loop)"),
          consent_owned: bool = typer.Option(False, help="Permission to test a live URL target"),
          save: Optional[str] = typer.Option(None, help="Save report to this path (default prompts)"),
          no_save: bool = typer.Option(False, help="Skip the save prompt"),
          api: str = typer.Option("http://localhost:8000"),
          api_key: str = typer.Option("dev-key-1", envvar="KYBER_API_KEY")):
    """Prompt an LLM that does the work inside the Kyber sandbox.

    Example: kyber agent --target ./app.zip --goal "find RCE and explain exploitability"
    Uses settings.llm_model via LiteLLM (pip install -e ".[llm]"); without a key
    it runs a deterministic fallback sweep so the command still returns value.
    """
    from kyber.server import ServerError

    typer.echo("Kyber agent — LLM red-team in sandbox")
    try:
        state = ensure_api_up(api)
    except ServerError as e:
        typer.echo(f"Cannot reach API: {e}")
        raise typer.Exit(1)
    typer.echo("API started." if state == "started" else "API ready (already running).")

    kind: Optional[str] = None
    value: Optional[str] = target
    if value and os.path.exists(value):
        kind = "file"
    elif value:
        kind = _guess_kind(value)
        if kind == "file":
            typer.echo(f"No such file: {value}")
            raise typer.Exit(1)
    else:
        kind = _prompt_kind()
        if kind == "file":
            value = _prompt_path()
            if value is None:
                typer.echo("Aborted.")
                return
        elif kind == "repo":
            value = typer.prompt("Repo URL", default="").strip()
            if not value:
                typer.echo("Aborted.")
                return
        else:
            value = typer.prompt("Service URL", default="").strip()
            if not value:
                typer.echo("Aborted.")
                return
    if kind == "url" and not consent_owned:
        consent_owned = typer.confirm(
            "Do you own this target / have permission to test it?", default=False)
        if not consent_owned:
            typer.echo("Aborted (consent is required for live targets).")
            return
    if not goal:
        goal = typer.prompt("Agent goal",
                            default="Find exploitable vulnerabilities and explain impact.").strip()
        if not goal:
            goal = "Find exploitable vulnerabilities and explain impact."
    typer.echo(f"Goal: {goal}")
    try:
        if kind == "file":
            s = _do_submit(api, api_key, value, None, None, "auto", "agent", False, goal)
        elif kind == "repo":
            s = _do_submit(api, api_key, None, value, None, "auto", "agent", False, goal)
        else:
            s = _do_submit(api, api_key, None, None, value, "auto", "agent", True, goal)
    except typer.BadParameter as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)
    scan_id = s["id"]
    c = _client(api, api_key)
    final = _wait_for_scan(c, scan_id)
    if final.get("status") != "done":
        typer.echo("Scan {} ended with status: {} ({})".format(
            scan_id, final.get("status"), final.get("error") or "no detail"))
        raise typer.Exit(1)
    findings = _fetch_findings(c, scan_id)
    _print_summary(scan_id, findings)
    if save:
        _save_findings(save, findings)
    elif not no_save:
        out = _prompt_save_path(scan_id)
        if out:
            _save_findings(out, findings)
    typer.echo(f"Fetch later with: kyber report {scan_id}")


@app.command()
def mcp():
    """Run the MCP server on stdio (for Claude Desktop / MCP clients)."""
    from kyber.mcp_server import serve_stdio

    serve_stdio()


@app.callback(invoke_without_command=True)
def callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        run_wizard("http://localhost:8000",
                   os.environ.get("KYBER_API_KEY", "dev-key-1"))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
