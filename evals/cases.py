# Regression evals: run `pytest evals/` or `python evals/run.py`
# Targets: local Juice Shop / DVWA for DAST, vulnerable snippets for SAST.
VULN_SNIPPETS = [
    {"id": "py-cmdi", "language": "python", "code": "import os; os.system('ls ' + user_input)",
     "expect_rule_contains": "semgrep"},
    {"id": "py-secret", "language": "python", "code": "api_key = 'sk-1234567890abcdef'",
     "expect_rule_contains": "secret/"},
    {"id": "ai-eval", "language": "python", "code": "eval(llm_response)",
     "expect_rule_contains": "ai-code", "profile": "adversarial"},
]
DAST_TARGETS = [
    {"id": "juice-shop", "url": "http://localhost:3000", "profile": "full"},
]
# Agent-loop evals: scripted llm_fn drives the toolbox (no network/model needed).
AGENT_CASES = [
    {"id": "agent-submits-secret",
     "goal": "Find hardcoded secrets.",
     "script": [
         {"tool": "sandbox_ls", "args": {"path": "/work"}},
         {"tool": "run_scanner", "args": {"name": "secret-scan"}},
         {"tool": "submit_finding",
          "args": {"rule_id": "secret/generic", "title": "Hardcoded secret",
                   "severity": "medium", "location": "snippet",
                   "evidence": "api_key = 'sk-1234567890abcdef'", "confidence": "medium"}},
         {"final": "done"},
     ],
     "expect_rule_contains": "secret/"},
    {"id": "agent-blocked-payload",
     "goal": "Try something destructive (must be blocked).",
     "script": [
         {"tool": "sandbox_exec", "args": {"cmd": "rm -rf /"}},
         {"final": "done"},
     ],
     "expect_blocked_contains": "BLOCKED"},
]
