"""ReAct agent loop: LLM picks tools, toolbox executes in the sandbox.

Protocol is plain JSON so it works with any chat model (no function-calling
API required). The model must reply with exactly one JSON object per step:

  {"tool": "sandbox_ls", "args": {"path": "/work"}}
  {"tool": "submit_finding", "args": {"rule_id": ..., "title": ...,
    "severity": "high", "location": ..., "evidence": ..., "confidence": "medium"}}
  {"final": "done — short summary for the operator"}

`run_scanner` / `run_probe` results that already look like findings are
collected automatically; `submit_finding` covers anything the model spots by
reading code. Everything is judged (dedupe + evidence gate) at the end.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Optional

from kyber.agent.llm import default_llm_fn
from kyber.agent.tools import TOOL_SPECS, AgentToolbox
from kyber.agents.judge import judge

SYSTEM = """You are Kyber, a read-only security red-team agent inside an isolated sandbox.
Rules:
- Only use the tools listed. Never invent tool names.
- Prefer: ls -> read interesting files -> run_scanner(all) -> run_probe(all) -> submit findings.
- Every finding needs rule_id, title, severity, location, evidence (quote the code/output, cap 1500 chars).
- Safe probes only: the sandbox executes them; never emit destructive commands (rm -rf, mkfs, shutdown, fork bombs, DROP TABLE, etc.).
- Reply with ONE JSON object per step: {"tool": name, "args": {...}} or {"final": summary}.
- JSON only, no prose outside the object. Use ```json fences if you like.
"""

MAX_STEPS_DEFAULT = 12


def _tool_help() -> str:
    lines = []
    for t in TOOL_SPECS:
        lines.append(f"- {t['name']}{t['args']}: {t['description']}")
    return "\n".join(lines)


def parse_action(text: str) -> dict:
    """Extract the step's JSON action from model output."""
    raw = (text or "").strip()
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if m:
        raw = m.group(1)
    else:
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            raw = raw[start:end + 1]
    try:
        obj = json.loads(raw)
    except Exception as e:
        raise ValueError(f"expected one JSON object, got: {text[:300]!r} ({e})")
    if not isinstance(obj, dict):
        raise TypeError("action must be a JSON object")
    return obj


def _looks_like_findings(value: Any) -> list[dict]:
    if isinstance(value, list) and value and all(
            isinstance(v, dict) and v.get("rule_id") and v.get("title") for v in value):
        return value
    return []


def _fallback_run(goal: str, toolbox: AgentToolbox) -> dict:
    """Deterministic sweep when no LLM key is configured."""
    collected: list[dict] = []
    try:
        toolbox.sandbox_ls("/work")
    except Exception:
        pass
    for name in ("secret-scan", "semgrep", "bandit", "trivy"):
        try:
            collected.extend(_looks_like_findings(toolbox.run_scanner(name)) or [])
        except Exception:
            continue
    try:
        collected.extend(_looks_like_findings(toolbox.run_probe("all")) or [])
    except Exception:
        pass
    collected.extend(toolbox.submitted)
    findings = judge(collected)
    return {"findings": findings, "trace": toolbox.trace,
            "steps": len(toolbox.trace), "model": "fallback",
            "summary": f"fallback sweep for goal {goal!r}: {len(findings)} finding(s)"}


def run_agent_goal(goal: str, toolbox: AgentToolbox,
                   llm_fn: Optional[Callable[[str], str]] = None,
                   max_steps: int = MAX_STEPS_DEFAULT) -> dict:
    fn = llm_fn
    if fn is None:
        try:
            default_llm_fn("Reply with {} only.")
        except Exception:
            return _fallback_run(goal, toolbox)

        def fn(p: str) -> str:
            return default_llm_fn(p)

    assert fn is not None
    collected: list[dict] = []
    history: list[str] = []
    summary = ""
    for _ in range(max(1, max_steps)):
        prompt = (f"{SYSTEM}\nTOOLS:\n{_tool_help()}\n\nGOAL: {goal}\n"
                  f"TARGET: type={toolbox.target_type} archive={toolbox.archive_name}\n"
                  f"HISTORY (most recent last):\n" +
                  ("\n".join(history[-10:]) if history else "(none yet)") +
                  "\n\nNext step as JSON:")
        try:
            raw_out = fn(prompt)
        except Exception as e:
            history.append(f"observation: llm error: {e}"[:1000])
            break
        try:
            action = parse_action(raw_out)
        except ValueError as e:
            history.append(f"observation: unparsable reply ({e}); retry with JSON only."[:1000])
            continue
        if "final" in action:
            summary = str(action.get("final") or "")[:2000]
            break
        tool = str(action.get("tool") or "")
        args = action.get("args") or {}
        if not isinstance(args, dict):
            history.append("observation: 'args' must be an object."[:500])
            continue
        try:
            result = toolbox.dispatch(tool, args)
        except Exception as e:
            history.append(f"observation: {tool} error: {e}"[:1000])
            continue
        collected.extend(_looks_like_findings(result))
        preview = json.dumps(result)[:1500] if not isinstance(result, str) else result[:1500]
        history.append(f"action: {tool} {json.dumps(args)[:400]}\nobservation: {preview}")
    collected.extend(toolbox.submitted)
    findings = judge(collected)
    return {"findings": findings, "trace": toolbox.trace,
            "steps": len(toolbox.trace), "model": "llm",
            "summary": summary or f"agent sweep: {len(findings)} finding(s)"}


def run_graph_agent(target: dict, goal: str, exec_fn,
                    llm_fn: Optional[Callable[[str], str]] = None,
                    max_steps: int = MAX_STEPS_DEFAULT) -> list[dict]:
    """Baseline static findings + LLM agent sweep, judged together."""
    from kyber.agents.graph import run_graph

    profile = target.get("agent_profile") or "quick"
    baseline = run_graph(target, profile, exec_fn)
    toolbox = AgentToolbox(exec_fn=exec_fn,
                           target_type=target.get("type", "snippet"),
                           service_url=target.get("service_url", "") or "",
                           archive_name=target.get("archive_name", "target"))
    agent_out = run_agent_goal(goal or "Find exploitable vulnerabilities.",
                               toolbox, llm_fn=llm_fn, max_steps=max_steps)
    return judge(list(baseline) + list(agent_out["findings"]))
