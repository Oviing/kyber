from typer.testing import CliRunner

from kyber import cli
from kyber.cli import app

runner = CliRunner()

FINDINGS = [
    {"rule_id": "secret/generic", "title": "Hardcoded secret", "severity": "medium",
     "confidence": "medium", "location": "snippet", "evidence": "redacted", "tool": "secret-scan"},
    {"rule_id": "probe/xss", "title": "Possible XSS", "severity": "low",
     "confidence": "low", "location": "snippet", "evidence": "e", "tool": "safe-probe"},
]


def _mock_run(monkeypatch, submitted=None):
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(cli, "_do_submit",
                        lambda *a, **k: submitted or {"id": "s1", "status": "done"})
    monkeypatch.setattr(cli, "_wait_for_scan", lambda c, sid: {"status": "done"})
    monkeypatch.setattr(cli, "_fetch_findings", lambda c, sid: FINDINGS)


def test_wizard_file_flow(monkeypatch, tmp_path):
    target = tmp_path / "vuln.py"
    target.write_text("x = 1", encoding="utf-8")
    _mock_run(monkeypatch)
    # kind=file (default), path, profile (default), save (skip)
    result = runner.invoke(app, ["wizard"], input=f"\n{target}\n\n\n")
    assert result.exit_code == 0, result.output
    assert "2 finding(s)" in result.output
    assert "secret/generic" in result.output
    assert "kyber report s1" in result.output


def test_wizard_uses_returned_scan_id(monkeypatch, tmp_path):
    target = tmp_path / "vuln.py"
    target.write_text("x = 1", encoding="utf-8")
    _mock_run(monkeypatch, submitted={"id": "scan-9", "status": "done"})
    result = runner.invoke(app, ["wizard"], input=f"\n{target}\n\n\n")
    assert result.exit_code == 0, result.output
    assert "kyber report scan-9" in result.output


def test_wizard_target_option_skips_prompts(monkeypatch, tmp_path):
    target = tmp_path / "vuln.py"
    target.write_text("x = 1", encoding="utf-8")
    _mock_run(monkeypatch, submitted={"id": "s2", "status": "done"})
    result = runner.invoke(app, ["wizard", "--target", str(target)], input="\n\n")
    assert result.exit_code == 0, result.output
    assert "Scan what?" not in result.output


def test_wizard_invalid_profile_option(monkeypatch, tmp_path):
    target = tmp_path / "vuln.py"
    target.write_text("x = 1", encoding="utf-8")
    _mock_run(monkeypatch)
    result = runner.invoke(app, ["wizard", "--target", str(target), "--profile", "bogus"],
                           input="")
    assert result.exit_code == 1
    assert "Invalid profile" in result.output


def test_wizard_url_without_consent_aborts(monkeypatch):
    called = []
    _mock_run(monkeypatch)
    monkeypatch.setattr(cli, "_do_submit", lambda *a, **k: called.append(1) or {"id": "x"})
    # kind=url, service url, decline consent
    result = runner.invoke(app, ["wizard"], input="url\nhttp://localhost:3000\nn\n")
    assert result.exit_code == 0, result.output
    assert "Aborted" in result.output
    assert called == []


def test_wizard_api_unreachable_exits_1(monkeypatch):
    from kyber.server import ServerError

    def boom(api):
        raise ServerError("port 8000 is occupied")

    monkeypatch.setattr(cli, "ensure_api_up", boom)
    result = runner.invoke(app, ["wizard"], input="")
    assert result.exit_code == 1
    assert "Cannot reach API" in result.output


def test_bare_kyber_runs_wizard(monkeypatch):
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    result = runner.invoke(app, [], input="\n\n")
    assert result.exit_code == 0, result.output
    assert "Aborted." in result.output


def test_doctor_reports(monkeypatch):
    monkeypatch.setattr(cli, "is_healthy", lambda api, timeout=3.0: False)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "python:" in result.output
    assert "unreachable" in result.output
    assert "docker:" in result.output


def test_down_no_server(monkeypatch, tmp_path):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    result = runner.invoke(app, ["down"])
    assert result.exit_code == 0, result.output
    assert "no managed server" in result.output
