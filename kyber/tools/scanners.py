"""SAST/SCA/DAST tool wrappers. Each runs a command inside the sandbox and parses output."""
import json
import re


def parse_semgrep(output: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(output) if output.strip().startswith("{") else {}
        for r in data.get("results", []):
            findings.append(
                {
                    "rule_id": f"semgrep/{r.get('check_id', 'rule')}",
                    "title": r.get("extra", {}).get("message", "semgrep finding"),
                    "severity": r.get("extra", {}).get("severity", "MEDIUM").lower(),
                    "location": f"{r.get('path', '?')}:{r.get('start', {}).get('line', '?')}",
                    "evidence": (r.get("extra", {}).get("lines", "") or "")[:2000],
                    "tool": "semgrep",
                    "cwe": _cwe_from_text(r.get("extra", {}).get("message", "")),
                }
            )
    except Exception:
        # Fallback: line-based grep of known dangerous patterns.
        for i, line in enumerate(output.splitlines(), 1):
            if re.search(r"eval\(|exec\(|subprocess|os\.system|pickle\.loads", line):
                findings.append(
                    {
                        "rule_id": "semgrep/fallback-dangerous-func",
                        "title": "Dangerous function usage",
                        "severity": "high",
                        "location": f"line:{i}",
                        "evidence": line[:500],
                        "tool": "semgrep",
                    }
                )
    return findings


def parse_bandit(output: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(output) if output.strip().startswith("{") else {}
        for r in data.get("results", []):
            findings.append(
                {
                    "rule_id": f"bandit/{r.get('test_id', 'rule')}",
                    "title": r.get("issue_text", "bandit finding"),
                    "severity": r.get("issue_severity", "MEDIUM").lower(),
                    "confidence": r.get("issue_confidence", "medium").lower(),
                    "location": f"{r.get('filename', '?')}:{r.get('line_number', '?')}",
                    "evidence": (r.get("code", "") or "")[:2000],
                    "tool": "bandit",
                }
            )
    except Exception:
        pass
    return findings


def parse_nuclei(output: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            findings.append(
                {
                    "rule_id": f"nuclei/{e.get('template-id', 'unknown')}",
                    "title": e.get("info", {}).get("name", "nuclei finding"),
                    "severity": e.get("info", {}).get("severity", "medium").lower(),
                    "location": e.get("host", e.get("matched-at", "?")),
                    "evidence": line[:2000],
                    "tool": "nuclei",
                }
            )
        except Exception:
            continue
    return findings


def _cwe_from_text(text: str) -> str | None:
    m = re.search(r"CWE-(\d+)", text)
    return f"CWE-{m.group(1)}" if m else None


SAST_COMMANDS = {
    "python": [
        "semgrep --config auto --json --quiet /work 2>/dev/null || true",
        "bandit -r /work -f json -q 2>/dev/null || true",
        "gitleaks detect --no-git -v /work 2>/dev/null || true",
    ],
    "javascript": [
        "semgrep --config auto --json --quiet /work 2>/dev/null || true",
        "npx eslint-plugin-security /work 2>/dev/null || true",
    ],
}

SCA_COMMANDS = [
    "trivy fs --format json --quiet /work 2>/dev/null || true",
]

DAST_COMMANDS = [
    "nuclei -u {target} -json -silent 2>/dev/null || true",
    "zap-baseline.py -t {target} -J /tmp/zap.json 2>/dev/null; cat /tmp/zap.json 2>/dev/null || true",
]
