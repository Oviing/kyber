from typer.testing import CliRunner

from kyber.cli import app

runner = CliRunner()


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
