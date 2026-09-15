"""Terminal mission view: live read-only dashboard for one sandbox session.

Every section is best-effort — a failing data source renders as
"unavailable: ..." instead of crashing the dashboard. Nothing here mutates
the session.
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from kyber.sandbox import backends
from kyber.sandbox.common import SandboxError, home_dir


@dataclass
class Snapshot:
    name: str
    backend: str = "?"
    status: str = "?"
    image: str = "?"
    volume: str = "?"
    work_label: str = "?"
    files: list[str] = field(default_factory=list)
    logs: str = ""
    audit: str = ""
    stats: str = ""


def audit_tail(name: str, lines: int = 8) -> str:
    found: list[str] = []
    try:
        with open(os.path.join(home_dir(), "sandbox-audit.log"), encoding="utf-8") as fh:
            for line in fh:
                if f" {name} " in line or f" {name}" in line.rstrip()[-len(name) - 1:]:
                    found.append(line.rstrip())
    except OSError:
        return "n/a (no audit log yet)"
    if not found:
        return "no entries yet"
    return "\n".join(found[-lines:])


def _docker_files(name: str) -> list[str]:
    from kyber.sandbox import shell as shell_mod

    _code, out = shell_mod.exec_cmd(name, "ls -p /work")
    return [ln for ln in out.splitlines() if ln.strip()][:60]


def _docker_stats(container: str) -> str:
    try:
        out = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.CPUPerc}} cpu {{.MemUsage}}", container],
            capture_output=True, text=True, timeout=10, check=False)
    except Exception as e:
        return f"n/a ({e})"
    if out.returncode != 0:
        return "n/a (container not running?)"
    return (out.stdout or "").strip() or "n/a"


def collect_snapshot(name: str, backend: str = "auto") -> Snapshot:
    """Gather one read-only snapshot. Raises SandboxError if no such session."""
    snap = Snapshot(name=name)
    try:
        sessions = backends.list_all(backend)
    except SandboxError as e:
        raise SandboxError(str(e)) from e
    match = next((s for s in sessions if s.name == name), None)
    if match is None:
        raise SandboxError(f"sandbox {name!r} not found "
                           f"(kyber sandbox up --name {name})")
    snap.backend, snap.status, snap.image = match.backend, match.status, match.image
    vol = match.volume or "?"
    snap.volume = vol
    snap.work_label = f"host mount {vol}" if os.path.isabs(vol) and os.path.isdir(vol) \
        and match.backend == "docker" and not vol.startswith("kyber-ws-") else vol
    if match.backend == "local":
        try:
            entries = sorted(os.listdir(vol))
            snap.files = [e + ("/" if os.path.isdir(os.path.join(vol, e)) else "")
                          for e in entries[:60]]
        except OSError as e:
            snap.files = [f"unavailable: {e}"]
    else:
        try:
            snap.files = _docker_files(name)
        except SandboxError as e:
            snap.files = [f"unavailable: {e}"]
        snap.stats = _docker_stats(match.container)
    try:
        snap.logs = backends.logs(name, backend=backend, tail=15)
    except SandboxError as e:
        snap.logs = f"unavailable: {e}"
    snap.audit = audit_tail(name)
    return snap


def render(snap: Snapshot) -> Group:
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold magenta")
    header.add_column()
    header.add_row("session", f"⬢ {snap.name}  ({snap.backend}, {snap.status})")
    header.add_row("/work", snap.work_label)
    header.add_row("image", snap.image)
    if snap.stats:
        header.add_row("stats", snap.stats)

    tree = Tree(f"[cyan]/work[/cyan] [dim]({len(snap.files)} entries)[/dim]")
    for entry in snap.files[:40]:
        tree.add(f"[cyan]{entry}[/cyan]" if entry.endswith("/") else entry)

    return Group(
        Panel(header, title="⬢ kyber sandbox", border_style="magenta"),
        Panel(tree, title="workspace", border_style="cyan"),
        Panel(snap.logs[-3000:] or "(empty)", title="recent logs", border_style="blue"),
        Panel(snap.audit[-2000:] or "(empty)", title="audit trail", border_style="dim"),
    )


def run(name: str, backend: str = "auto", interval: float = 2.0, once: bool = False) -> None:
    """Live dashboard until Ctrl-C, or a single static render with once=True."""
    console = Console()
    if once:
        console.print(render(collect_snapshot(name, backend)))
        return
    with Live(render(collect_snapshot(name, backend)), console=console,
              refresh_per_second=max(0.5, min(4.0, 1.0 / max(interval, 0.25))),
              screen=False) as live:
        while True:
            time.sleep(interval)
            live.update(render(collect_snapshot(name, backend)))
