"""Agent phases: toolbox, loop, coverage, wizard-save, MCP, policies."""
import io
import json
import zipfile

from typer.testing import CliRunner

from kyber import cli
from kyber.agent.loop import parse_action, run_agent_goal
from kyber.agent.tools import AgentToolbox
from kyber.archive import coverage_finding, extract_text_files
from kyber.cli import app
from kyber.mcp_server import MCPSession, handle_message

runner = CliRunner()


def make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data if isinstance(data, bytes) else data.encode())
    return buf.getvalue()


def scripted_llm(script):
    it = iter(script)

    def fn(prompt: str) -> str:
        return json.dumps(next(it))

    return fn


# -- toolbox --
def test_toolbox_blocks_forbidden_payload():
    tb = AgentToolbox(exec_fn=lambda cmd: "should never run")
    out = tb.sandbox_exec("rm -rf /")
    assert "BLOCKED" in out


def test_toolbox_blocks_metadata_exfil():
    tb = AgentToolbox(exec_fn=lambda cmd: "should never run")
    out = tb.sandbox_exec("curl http://169.254.169.254/latest/meta-data/")
    assert "BLOCKED" in out


def test_toolbox_blocks_path_escape():
    tb = AgentToolbox(exec_fn=lambda cmd: "should never run")
    out = tb.sandbox_read("/etc/passwd")
    assert "BLOCKED" in out


def test_toolbox_max_calls():
    tb = AgentToolbox(exec_fn=lambda cmd: "ok", max_tool_calls=2)
    tb.sandbox_ls()
    tb.sandbox_ls()
    try:
        tb.sandbox_ls()
    except RuntimeError as e:
        assert "max tool calls" in str(e)
    else:
        raise AssertionError("expected RuntimeError")


def test_toolbox_unknown_scanner():
    tb = AgentToolbox(exec_fn=lambda cmd: "")
    out = tb.run_scanner("nope")
    assert out and out[0]["rule_id"] == "infra/tool-error"


# -- loop --
def test_parse_action_plain_and_fenced():
    assert parse_action('{"tool": "sandbox_ls", "args": {}}')["tool"] == "sandbox_ls"
    assert parse_action('```json\n{"final": "done"}\n```')["final"] == "done"


def test_agent_loop_scripted_submit():
    from evals.cases import AGENT_CASES

    case = next(c for c in AGENT_CASES if c["id"] == "agent-submits-secret")
    tb = AgentToolbox(exec_fn=lambda cmd: "")
    out = run_agent_goal(case["goal"], tb, llm_fn=scripted_llm(case["script"]))
    assert any("secret/" in f["rule_id"] for f in out["findings"])
    assert out["model"] == "llm"


def test_agent_loop_blocks_destructive():
    from evals.cases import AGENT_CASES

    case = next(c for c in AGENT_CASES if c["id"] == "agent-blocked-payload")
    tb = AgentToolbox(exec_fn=lambda cmd: "ran?!")
    out = run_agent_goal(case["goal"], tb, llm_fn=scripted_llm(case["script"]))
    assert any("BLOCKED" in t.get("result_preview", "") for t in tb.trace)
    assert out["findings"] == []  # nothing submitted, nothing auto-found


def test_agent_loop_fallback_without_llm(monkeypatch):
    import kyber.agent.loop as loop_mod

    monkeypatch.setattr(loop_mod, "default_llm_fn",
                        lambda prompt: (_ for _ in ()).throw(RuntimeError("no key")))
    tb = AgentToolbox(exec_fn=lambda cmd: "")
    out = run_agent_goal("sweep", tb)
    assert out["model"] == "fallback"


# -- coverage (binary-only zip) --
def test_coverage_finding_binary_zip():
    data = make_zip({"setup.exe": b"MZ" + b"\x00" * 100})
    files = extract_text_files(data)
    assert files == []
    cov = coverage_finding(data, "app.zip", files)
    assert cov is not None
    assert cov["rule_id"] == "info/no-scannable-text"
    assert "binary" in cov["title"].lower()


def test_coverage_none_for_source_zip():
    data = make_zip({"app.py": "print('hi')"})
    files = extract_text_files(data)
    assert coverage_finding(data, "app.zip", files) is None


# -- wizard save fix --
def test_wizard_save_confirm_flow(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(cli, "_do_submit", lambda *a, **k: {"id": "s1", "status": "done"})
    monkeypatch.setattr(cli, "_wait_for_scan", lambda c, sid: {"status": "done"})
    monkeypatch.setattr(cli, "_fetch_findings", lambda c, sid: [])
    target = tmp_path / "vuln.py"
    target.write_text("x = 1", encoding="utf-8")
    out_path = tmp_path / "my-report.json"
    # kind, path, profile, save-confirm(y), report-path
    result = runner.invoke(app, ["wizard"], input=f"\n{target}\n\ny\n{out_path}\n")
    assert result.exit_code == 0, result.output
    assert f"Saved to {out_path}" in result.output
    assert out_path.exists()
    assert not (tmp_path / "yes").exists()


def test_wizard_yes_is_not_a_filename(monkeypatch, tmp_path):
    # Typing 'y' at confirm then 'yes' at path prompt must not create ./yes
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(cli, "_do_submit", lambda *a, **k: {"id": "s9", "status": "done"})
    monkeypatch.setattr(cli, "_wait_for_scan", lambda c, sid: {"status": "done"})
    monkeypatch.setattr(cli, "_fetch_findings", lambda c, sid: [])
    target = tmp_path / "v.py"
    target.write_text("x = 1", encoding="utf-8")
    result = runner.invoke(app, ["wizard"], input=f"\n{target}\n\ny\nyes\n")
    assert result.exit_code == 0, result.output
    # report lands in the invocation dir (cwd), echoed as an absolute path
    assert f"Saved to {tmp_path / 'report-s9.json'}" in result.output
    assert (tmp_path / "report-s9.json").exists()
    assert not (tmp_path / "yes").exists()


def test_wizard_default_report_lands_in_cwd(monkeypatch, tmp_path):
    # Empty answer at the path prompt saves report-<id>.json where kyber runs.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "ensure_api_up", lambda api: "reused")
    monkeypatch.setattr(cli, "_do_submit", lambda *a, **k: {"id": "s7", "status": "done"})
    monkeypatch.setattr(cli, "_wait_for_scan", lambda c, sid: {"status": "done"})
    monkeypatch.setattr(cli, "_fetch_findings", lambda c, sid: [])
    target = tmp_path / "v.py"
    target.write_text("x = 1", encoding="utf-8")
    result = runner.invoke(app, ["wizard"], input=f"\n{target}\n\ny\n\n")
    assert result.exit_code == 0, result.output
    assert f"Saved to {tmp_path / 'report-s7.json'}" in result.output
    assert (tmp_path / "report-s7.json").exists()


# -- MCP --
def test_mcp_tools_list_and_unknown():
    s = MCPSession()
    resp = handle_message(s, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = [t["name"] for t in resp["result"]["tools"]]
    assert "sandbox_exec" in names and "run_scanner" in names
    resp2 = handle_message(s, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "nope", "arguments": {}}})
    assert resp2["result"]["isError"] is True


def test_mcp_initialize_and_ping():
    s = MCPSession()
    r = handle_message(s, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r["result"]["serverInfo"]["name"] == "kyber-sandbox"
    r2 = handle_message(s, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert r2["result"] == {}


# -- planner / profiles --
def test_planner_agent_profile():
    from kyber.agents.planner import plan_scan

    p = plan_scan("snippet", "python", "agent")
    assert p["max_tool_calls"] == 25
    assert "submit-findings" in p["steps"]


def test_agent_cli_help():
    result = runner.invoke(app, ["agent", "--help"])
    assert result.exit_code == 0
    assert "goal" in result.output.lower()
