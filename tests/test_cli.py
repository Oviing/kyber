import pytest
from typer.testing import CliRunner

from kyber.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _no_real_docker(monkeypatch):
    """Isolate CLI end-to-end tests from any real daemon/containers."""
    from kyber.sandbox import backends

    monkeypatch.setattr(backends, "_docker_has", lambda name: False)


def test_help_lists_sandbox():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "sandbox" in result.output
    assert "doctor" in result.output


def test_sandbox_help_lists_commands():
    result = runner.invoke(app, ["sandbox", "--help"])
    assert result.exit_code == 0
    for cmd in ("up", "shell", "exec", "ls", "logs", "snapshot", "down", "build"):
        assert cmd in result.output


def test_bare_kyber_prints_quickstart(monkeypatch, tmp_path):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "sandbox shell" in result.output
    assert "Traceback" not in result.output


def test_sandbox_up_error_is_clean(monkeypatch):
    from kyber.sandbox import backends as backends_mod

    def boom(*a, **k):
        from kyber.sandbox.common import SandboxError
        raise SandboxError("docker daemon unreachable at unix:///x: nope")

    monkeypatch.setattr(backends_mod, "up", boom)
    result = runner.invoke(app, ["sandbox", "up", "--name", "demo"])
    assert result.exit_code == 1
    assert "Error: docker daemon unreachable" in result.output
    assert "Traceback" not in result.output


def test_sandbox_up_local_backend_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    result = runner.invoke(
        app, ["sandbox", "up", "--backend", "local", "--allow-unsafe", "--name", "demo"])
    assert result.exit_code == 0, result.output
    assert "Local sandbox 'demo' up" in result.output
    assert (tmp_path / "workspaces" / "demo").is_dir()


def test_sandbox_exec_local_backend_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    up = runner.invoke(
        app, ["sandbox", "up", "--backend", "local", "--allow-unsafe", "--name", "demo"])
    assert up.exit_code == 0, up.output
    result = runner.invoke(
        app, ["sandbox", "exec", "--backend", "local", "--allow-unsafe",
              "demo", "--cmd", "echo hello-local"])
    assert result.exit_code == 0, result.output
    assert "hello-local" in result.output


def test_sandbox_up_local_needs_allow_unsafe(monkeypatch, tmp_path):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    result = runner.invoke(app, ["sandbox", "up", "--backend", "local", "--name", "demo"])
    assert result.exit_code == 1
    assert "--allow-unsafe" in result.output


def test_sandbox_up_auto_without_daemon_names_local_retry(monkeypatch):
    from kyber.sandbox import docker_env

    monkeypatch.setattr(docker_env, "daemon_reachable",
                        lambda timeout=5: (False, "docker daemon unreachable at unix:///x"))
    result = runner.invoke(app, ["sandbox", "up", "--name", "demo"])
    assert result.exit_code == 1
    assert "--backend local --allow-unsafe" in result.output


def test_sandbox_help_lists_view():
    result = runner.invoke(app, ["sandbox", "--help"])
    assert result.exit_code == 0
    assert "view" in result.output


def test_sandbox_view_once_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    up = runner.invoke(
        app, ["sandbox", "up", "--backend", "local", "--allow-unsafe", "--name", "demo"])
    assert up.exit_code == 0, up.output
    result = runner.invoke(app, ["sandbox", "view", "--backend", "local", "demo", "--once"])
    assert result.exit_code == 0, result.output
    assert "demo" in result.output


def test_sandbox_up_mount_passes_through(monkeypatch, tmp_path):
    from kyber.sandbox import backends as backends_mod

    proj = tmp_path / "proj"
    proj.mkdir()
    seen = {}

    def fake_up(name, **kwargs):
        seen.update(kwargs)
        from kyber.sandbox.common import SandboxInfo
        return SandboxInfo(name=name, container="c", network="n",
                           volume=kwargs.get("mount") or "v", image="i",
                           backend="docker")

    monkeypatch.setattr(backends_mod, "up", fake_up)
    result = runner.invoke(app, ["sandbox", "up", "--name", "demo", "--mount", str(proj)])
    assert result.exit_code == 0, result.output
    assert seen.get("mount") == str(proj)
    assert "host mount" in result.output


def test_sandbox_up_mount_error_is_clean(monkeypatch, tmp_path):
    result = runner.invoke(
        app, ["sandbox", "up", "--backend", "docker",
              "--name", "demo", "--mount", str(tmp_path / "nope")])
    assert result.exit_code != 0


def test_sandbox_up_with_local_tools_end_to_end(monkeypatch, tmp_path):
    from kyber.sandbox import tools as tools_mod

    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok-live")
    result = runner.invoke(
        app, ["sandbox", "up", "--backend", "local", "--allow-unsafe",
              "--name", "demo", "--with", "claude", "--yes"])
    assert result.exit_code == 0, result.output
    assert "claude" in result.output
    assert tools_mod.is_consented(tools_mod.load_manifest("claude"))
    out = runner.invoke(
        app, ["sandbox", "exec", "--backend", "local", "--allow-unsafe",
              "demo", "--cmd", "echo token=$CLAUDE_CODE_OAUTH_TOKEN"])
    assert out.exit_code == 0, out.output
    assert "token=tok-live" in out.output


def test_sandbox_build_unknown_tool_is_clean_error():
    result = runner.invoke(app, ["sandbox", "build", "--with", "nope"])
    assert result.exit_code == 1
    assert "unknown tool" in result.output


def test_sandbox_tools_and_consent_commands(monkeypatch, tmp_path):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    result = runner.invoke(app, ["sandbox", "tools"])
    assert result.exit_code == 0, result.output
    assert "claude" in result.output and "codex" in result.output
    result = runner.invoke(app, ["sandbox", "consent"])
    assert result.exit_code == 0
    assert "pending" in result.output
    result = runner.invoke(app, ["sandbox", "consent", "--revoke", "claude"])
    assert "No consent grant" in result.output
