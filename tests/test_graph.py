from kyber.agents.graph import run_graph


def test_graph_static_secret_scan_no_docker():
    target = {"type": "snippet", "language": "python",
              "snippet": "api_key = 'sk-1234567890abcdef'"}
    out = run_graph(target, "quick", exec_fn=lambda cmd: "")
    assert any(f["rule_id"].startswith("secret/") for f in out)


def test_graph_adversarial_ai_code():
    target = {"type": "snippet", "language": "python",
              "snippet": "eval(llm_response)\nimport os"}
    out = run_graph(target, "adversarial", exec_fn=lambda cmd: "")
    assert any("ai-code" in f["rule_id"] for f in out)


def test_planner_profiles():
    from kyber.agents.planner import plan_scan
    assert plan_scan("snippet", "python", "quick")["mode"] == "static"
    assert plan_scan("url", "auto", "full")["mode"] == "dast"
