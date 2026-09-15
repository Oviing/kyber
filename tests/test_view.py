"""Mission view dashboard tests (read-only; faked data sources)."""
import pytest

from kyber.sandbox import backends, view
from kyber.sandbox.common import SandboxError, SandboxInfo


def _info(**kw):
    base = {"name": "demo", "container": "kyber-sb-demo", "network": "n",
            "volume": "kyber-ws-demo", "image": "img", "status": "running",
            "backend": "docker"}
    base.update(kw)
    return SandboxInfo(**base)


def test_collect_missing_session_is_clean_error(monkeypatch):
    monkeypatch.setattr(backends, "list_all", lambda backend="auto", client=None: [])
    with pytest.raises(SandboxError, match="not found"):
        view.collect_snapshot("ghost")


def test_collect_local_session(monkeypatch, tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.py").write_text("x")
    (ws / "sub").mkdir()
    monkeypatch.setattr(backends, "list_all",
                        lambda backend="auto", client=None: [_info(backend="local",
                                                                  volume=str(ws))])
    monkeypatch.setattr(backends, "logs", lambda *a, **k: "logline\n")
    snap = view.collect_snapshot("demo")
    assert snap.backend == "local"
    assert "a.py" in snap.files
    assert "sub/" in snap.files
    assert "logline" in snap.logs


def test_collect_tolerates_failing_sections(monkeypatch):
    monkeypatch.setattr(backends, "list_all",
                        lambda backend="auto", client=None: [_info()])
    import kyber.sandbox.shell as shell_mod

    def boom(*a, **k):
        raise SandboxError("daemon down")

    monkeypatch.setattr(shell_mod, "exec_cmd", boom)
    monkeypatch.setattr(backends, "logs", boom)
    snap = view.collect_snapshot("demo")
    assert snap.files and snap.files[0].startswith("unavailable:")
    assert snap.logs.startswith("unavailable:")


def test_render_contains_session_identity(monkeypatch):
    from rich.console import Console

    monkeypatch.setattr(backends, "list_all",
                        lambda backend="auto", client=None: [_info()])
    import kyber.sandbox.shell as shell_mod

    monkeypatch.setattr(shell_mod, "exec_cmd", lambda *a, **k: (0, "a.py\n"))
    monkeypatch.setattr(backends, "logs", lambda *a, **k: "hi\n")
    monkeypatch.setattr(view, "audit_tail", lambda name, lines=8: "audit-1")
    console = Console(record=True, width=100)
    console.print(view.render(view.collect_snapshot("demo")))
    text = console.export_text()
    assert "demo" in text
    assert "a.py" in text
    assert "/work" in text
