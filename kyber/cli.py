from __future__ import annotations

import json
import os
import time
from typing import Optional

import httpx
import typer

MAX_SNIPPET_BYTES = 1_000_000

app = typer.Typer(help="Kyber red-team sandbox CLI", no_args_is_help=False)


@app.callback(invoke_without_command=True)
def callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


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
            f"{path!r} is not UTF-8 text. If it is an archive, upload a .zip; "
            f"otherwise unzip/convert to a text source file first ({e})") from e


@app.command()
def submit(file: Optional[str] = typer.Option(None, help="Snippet file to upload"),
           repo: Optional[str] = typer.Option(None, help="Git repo URL"),
           url: Optional[str] = typer.Option(None, help="Live service URL (requires --consent-owned)"),
           language: str = typer.Option("auto"),
           profile: str = typer.Option("quick"),
           consent_owned: bool = typer.Option(False, help="Confirm you own/have permission to test the target"),
           api: str = typer.Option("http://localhost:8000"),
           api_key: str = typer.Option("dev-key-1", envvar="KYBER_API_KEY")):
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
    s = c.post("/v1/scans", json={"target_id": t["id"], "profile": profile,
                                  "consent_owned": consent_owned}).json()
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
        for _ in range(120):
            s = c.get(f"/v1/scans/{scan_id}").json()
            if s["status"] in ("done", "failed", "timeout"):
                break
            time.sleep(3)
    if format == "sarif":
        typer.echo(json.dumps(c.get(f"/v1/scans/{scan_id}/report.sarif").json(), indent=2))
    else:
        typer.echo(json.dumps(c.get(f"/v1/scans/{scan_id}/findings").json(), indent=2))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
