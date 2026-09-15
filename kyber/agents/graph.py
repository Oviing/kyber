"""Minimal agent graph orchestrator (LangGraph-compatible shape, no hard dep).

Runs: plan -> scan -> (probes|adversarial) -> judge. Each step calls tools via exec_fn.
Set KYBER_USE_LANGGRAPH=1 + install kyber[llm] to swap in a real LangGraph graph later.
"""
from kyber.agents import adversarial as adv
from kyber.agents import exploiter, planner, scanner
from kyber.agents.judge import judge


def run_graph(target: dict, profile: str, exec_fn, dast_fetch_fn=None, llm_fn=None) -> list[dict]:
    plan = planner.plan_scan(target.get("type", "snippet"), target.get("language", "auto"), profile)
    raw: list[dict] = []
    calls = 0

    def guarded_exec(cmd: str) -> str:
        nonlocal calls
        calls += 1
        if calls > plan["max_tool_calls"]:
            raise RuntimeError("max tool calls exceeded")
        return exec_fn(cmd)

    if plan["mode"] == "dast":
        raw.extend(scanner.run_dast(target.get("service_url", ""), guarded_exec))
        if dast_fetch_fn:
            for req in exploiter.build_probe_requests(target.get("service_url")):
                try:
                    resp = dast_fetch_fn(req)
                    f = exploiter.score_probe_response(req["probe_id"], resp, req["target"])
                    if f:
                        raw.append(f)
                except Exception:
                    continue
    else:
        raw.extend(scanner.run_static(target.get("snippet", ""), plan["language"], guarded_exec))

    if profile == "full":
        # Static safe-probe hint: flag obvious injection sinks as info-level candidates.
        # Real HTTP probing happens in dast mode via dast_fetch_fn.
        pass

    if profile == "adversarial":
        raw.extend(adv.run_adversarial_static(target.get("snippet", "")))
        if llm_fn:
            for p in adv.get_prompts():
                try:
                    out = llm_fn(p["prompt"])
                    f = adv.score_model_output(p["id"], out)
                    if f:
                        raw.append(f)
                except Exception:
                    continue

    return judge(raw)
