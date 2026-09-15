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
