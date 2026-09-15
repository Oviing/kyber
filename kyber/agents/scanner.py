"""Scanner agent: runs SAST/SCA commands in sandbox, parses findings."""
from kyber.tools import scanners
from kyber.tools.safe_probes import static_secret_scan


def run_static(snippet: str, language: str, exec_fn) -> list[dict]:
    """exec_fn(cmd) -> output string. In prod exec_fn calls sandbox.exec; in tests it's stubbed."""
    findings: list[dict] = []
    findings.extend(static_secret_scan(snippet or ""))

    lang_key = "python" if "python" in language.lower() or "py" == language.lower() else (
        "javascript" if any(k in language.lower() for k in ("js", "node", "typescript")) else "python"
    )
    for cmd in scanners.SAST_COMMANDS.get(lang_key, scanners.SAST_COMMANDS["python"]):
        try:
            out = exec_fn(cmd)
        except Exception as e:
            findings.append(
                {"rule_id": "infra/tool-error", "title": f"Scanner tool failed: {cmd[:60]}",
                 "severity": "info", "confidence": "low", "location": "scanner",
                 "evidence": str(e)[:500], "tool": "scanner"}
            )
            continue
        if "semgrep" in cmd:
            findings.extend(scanners.parse_semgrep(out))
        elif "bandit" in cmd:
            findings.extend(scanners.parse_bandit(out))
    for cmd in scanners.SCA_COMMANDS:
        try:
            out = exec_fn(cmd)
            # trivy json parsing omitted in MVP: record raw hint if vulnerabilities mentioned
            if "VULNERABILITY" in out.upper() or "CVE-" in out:
                findings.append({"rule_id": "sca/vuln-deps", "title": "Vulnerable dependencies detected",
                                 "severity": "high", "confidence": "medium", "location": "deps",
                                 "evidence": out[:2000], "tool": "trivy"})
        except Exception:
            pass
    return findings


def run_dast(target_url: str, exec_fn) -> list[dict]:
    findings: list[dict] = []
    for template in scanners.DAST_COMMANDS:
        cmd = template.format(target=target_url)
        try:
            out = exec_fn(cmd)
        except Exception as e:
            findings.append({"rule_id": "infra/tool-error", "title": "DAST tool failed",
                             "severity": "info", "confidence": "low", "location": target_url,
                             "evidence": str(e)[:500], "tool": "dast"})
            continue
        findings.extend(scanners.parse_nuclei(out))
    return findings
