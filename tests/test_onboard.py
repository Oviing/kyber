"""Onboarding: init, demo, wizard guidance, doctor, agent gate, mcp install."""
import json

from typer.testing import CliRunner

from kyber import cli, onboard
from kyber.cli import app

runner = CliRunner()


class _Resp:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload


class _FakeClient:
    def post(self, url, **kwargs):
        if url == "/v1/targets":
            return _Resp({"id": "t1", "type": "snippet"})
        if url == "/v1/scans":
            return _Resp({"id": "s-demo", "status": "done"})
        raise AssertionError(url)

    def get(self, url, **kwargs):
        return _Resp({})


def _quiet_env(monkeypatch, tmp_path):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(onboard, "docker_hint", lambda: None)


# ---- init ----

def test_init_check_only_reports_next():
    result = runner.invoke(app, ["init", "--check-only"])
    assert result.exit_code == 0, result.output
    assert "kyber demo" in result.output


def test_init_creates_env_from_example(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env.example").write_text("API_KEYS=dev-key-1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", "--yes"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "API_KEYS=dev-key-1\n"


def test_init_check_only_does_not_create(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env.example").write_text("X=1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", "--check-only"])
    assert result.exit_code == 0, result.output
    assert not (tmp_path / ".env").exists()


# ---- demo ----

def test_demo_runs_sample_scan(monkeypatch, tmp_path):
    _quiet_env(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(cli, "_client", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(cli, "_wait_for_scan", lambda c, sid: {"status": "done"})
    monkeypatch.setattr(cli, "_fetch_findings", lambda c, sid: [
        {"rule_id": "secret/generic", "title": "Hardcoded secret", "severity": "medium",
         "confidence": "medium", "location": "snippet", "evidence": "redacted",
         "tool": "secret-scan"}])
    result = runner.invoke(app, ["demo", "--no-save"])
    assert result.exit_code == 0, result.output
    assert "1 finding(s)" in result.output
    assert "secret/generic" in result.output
    assert "kyber" in result.output  # next-step pointer


def test_demo_code_is_scannable():
    assert "AKIA" in onboard.DEMO_CODE or "sk-" in onboard.DEMO_CODE
    assert "os.system" in onboard.DEMO_CODE


# ---- wizard guidance ----

def test_wizard_first_run_banner(monkeypatch, tmp_path):
    _quiet_env(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(cli, "_do_submit", lambda *a, **k: {"id": "s1", "status": "done"})
    monkeypatch.setattr(cli, "_wait_for_scan", lambda c, sid: {"status": "done"})
    monkeypatch.setattr(cli, "_fetch_findings", lambda c, sid: [])
    target = tmp_path / "v.py"
    target.write_text("x = 1", encoding="utf-8")
    result = runner.invoke(app, ["wizard"], input=f"\n{target}\n\n\n")
    assert result.exit_code == 0, result.output
    assert "kyber demo" in result.output  # first-run banner
    assert "quick:" in result.output  # profile explainer
    # second run: banner gone
    result2 = runner.invoke(app, ["wizard"], input=f"\n{target}\n\n\n")
    assert "First time here?" not in result2.output


def test_wizard_shows_docker_hint(monkeypatch, tmp_path):
    _quiet_env(monkeypatch, tmp_path)
    monkeypatch.setattr(onboard, "docker_hint",
                        lambda: "Docker not found: scans run in limited fallback mode.")
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(cli, "_do_submit", lambda *a, **k: {"id": "s1", "status": "done"})
    monkeypatch.setattr(cli, "_wait_for_scan", lambda c, sid: {"status": "done"})
    monkeypatch.setattr(cli, "_fetch_findings", lambda c, sid: [])
    target = tmp_path / "v.py"
    target.write_text("x = 1", encoding="utf-8")
    result = runner.invoke(app, ["wizard"], input=f"\n{target}\n\n\n")
    assert result.exit_code == 0, result.output
    assert "fallback mode" in result.output


# ---- doctor ----

def test_doctor_reports_llm_and_mcp(monkeypatch):
    monkeypatch.setattr(cli, "is_healthy", lambda api, timeout=3.0: False)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "llm backend:" in result.output
    assert "mcp:" in result.output
    assert "sandbox images:" in result.output or "fallback scans only" in result.output


# ---- agent fallback gate ----

def test_agent_declining_fallback_aborts(monkeypatch, tmp_path):
    _quiet_env(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(onboard, "llm_ready", lambda: (False, "LLM_API_KEY is not set"))
    called = []
    monkeypatch.setattr(cli, "_do_submit", lambda *a, **k: called.append(1) or {"id": "x"})
    target = tmp_path / "v.py"
    target.write_text("x = 1", encoding="utf-8")
    result = runner.invoke(app, ["agent", "--target", str(target)], input="n\n")
    assert result.exit_code == 0, result.output
    assert "Aborted" in result.output
    assert called == []


def test_agent_fallback_ok_skips_prompt(monkeypatch, tmp_path):
    _quiet_env(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(onboard, "llm_ready", lambda: (False, "LLM_API_KEY is not set"))
    monkeypatch.setattr(cli, "_do_submit", lambda *a, **k: {"id": "s-ag", "status": "done"})
    monkeypatch.setattr(cli, "_wait_for_scan", lambda c, sid: {"status": "done"})
    monkeypatch.setattr(cli, "_fetch_findings", lambda c, sid: [])
    target = tmp_path / "v.py"
    target.write_text("x = 1", encoding="utf-8")
    result = runner.invoke(app, ["agent", "--target", str(target),
                                 "--goal", "find secrets", "--fallback-ok", "--no-save"])
    assert result.exit_code == 0, result.output
    assert "fallback sweep (--fallback-ok)" in result.output
    assert "Scan s-ag done" in result.output


# ---- mcp install ----

def test_mcp_install_dry_run():
    result = runner.invoke(app, ["mcp", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "would write" in result.output
    assert '"kyber"' in result.output


def test_install_mcp_client_merges_config(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}), encoding="utf-8")
    monkeypatch.setattr(onboard, "mcp_config_path", lambda client="claude-desktop": str(cfg))
    ok, msg = onboard.install_mcp_client()
    assert ok, msg
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["mcpServers"]["kyber"] == {"command": "kyber", "args": ["mcp"]}
    assert data["mcpServers"]["other"] == {"command": "x"}


def test_install_mcp_client_unknown_client():
    ok, msg = onboard.install_mcp_client("not-a-client")
    assert not ok
    assert "only claude-desktop" in msg


# ---- onboard helpers ----

def test_sandbox_images_status_no_docker(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
    ok, detail = onboard.sandbox_images_status()
    assert ok is None
    assert "docker" in detail.lower()


def test_llm_ready_returns_tuple():
    ok, detail = onboard.llm_ready()
    assert isinstance(ok, bool) and isinstance(detail, str)
