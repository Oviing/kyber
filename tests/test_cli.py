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
    from kyber.sandbox import shell as shell_mod

    def boom(*a, **k):
        from kyber.sandbox.shell import SandboxError
        raise SandboxError("docker not found — install Docker")

    monkeypatch.setattr(shell_mod, "up", boom)
    result = runner.invoke(app, ["sandbox", "up", "--name", "demo"])
    assert result.exit_code == 1
    assert "Error: docker not found" in result.output
    assert "Traceback" not in result.output
