"""Safe, read-only exploit probes. All payloads are non-destructive and sandbox-local.

Each probe returns a dict finding when the marker is observed, else None.
Probes run from the attacker container against the target container or static file.
"""
import re

PROBES = [
    {
        "id": "sqli/sleep",
        "title": "Possible SQL injection (time-based marker)",
        "payloads": ["' OR SLEEP(2)-- -", "' OR '1'='1"],
        "detect": re.compile(r"sleep|syntax.*sql|mysql|postgres|sqlite", re.IGNORECASE),
        "severity": "high",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "id": "xss/reflected",
        "title": "Possible reflected XSS (marker reflected)",
        "payloads": ["<script>kyber1337</script>", "\"><img src=x onerror=kyber1337>"],
        "detect": re.compile(r"kyber1337"),
        "severity": "medium",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
    {
        "id": "cmdi/marker",
        "title": "Possible OS command injection (marker in output)",
        "payloads": ["; echo kyber1337", "| echo kyber1337", "$(echo kyber1337)"],
        "detect": re.compile(r"kyber1337"),
        "severity": "high",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "id": "traversal/marker",
        "title": "Possible path traversal (local file read in sandbox)",
        "payloads": ["../../etc/hostname", "..%2F..%2Fetc%2Fhostname"],
        "detect": re.compile(r"[a-f0-9-]{6,}|linux|kyber", re.IGNORECASE),
        "severity": "medium",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "id": "ssrf/metadata",
        "title": "Possible SSRF (metadata IP attempt observed/blocked)",
        "payloads": ["http://169.254.169.254/latest/meta-data/"],
        "detect": re.compile(r"metadata|169\.254|blocked|forbidden|timeout", re.IGNORECASE),
        "severity": "medium",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
    },
]


def evaluate_probe(probe_id: str, response_text: str, location: str) -> dict | None:
    probe = next((p for p in PROBES if p["id"] == probe_id), None)
    if not probe:
        return None
    if probe["detect"].search(response_text or ""):
        return {
            "rule_id": f"probe/{probe_id}",
            "title": probe["title"],
            "severity": probe["severity"],
            "confidence": "medium",
            "cwe": probe.get("cwe"),
            "owasp": probe.get("owasp"),
            "location": location,
            "evidence": (response_text or "")[:2000],
            "tool": "safe-probe",
        }
    return None


def static_secret_scan(text: str, location: str = "snippet") -> list[dict]:
    """Regex fallback when gitleaks is unavailable."""
    out = []
    patterns = {
        "secret/aws-key": (r"AKIA[0-9A-Z]{16}", "Possible AWS key", "high"),
        "secret/private-key": (r"-----BEGIN (RSA )?PRIVATE KEY-----", "Private key in code", "high"),
        "secret/generic": (r"(?i)(api[_-]?key|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Hardcoded secret", "medium"),
    }
    for rule_id, (pat, title, sev) in patterns.items():
        if re.search(pat, text):
            out.append(
                {
                    "rule_id": rule_id,
                    "title": title,
                    "severity": sev,
                    "confidence": "medium",
                    "location": location,
                    "evidence": "redacted",
                    "tool": "secret-scan",
                }
            )
    return out
