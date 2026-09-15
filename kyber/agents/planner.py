"""Planner: choose mode, toolset, and step budget from target + profile."""
from kyber.models import ScanProfile, TargetType


def plan_scan(target_type: str, language: str, profile: str) -> dict:
    profile = ScanProfile(profile).value if profile in [p.value for p in ScanProfile] else "quick"
    lang = (language or "auto").lower()

    if target_type == TargetType.url.value:
        mode = "dast"
    else:
        mode = "static"

    if profile == "quick":
        steps = ["secret-scan", "semgrep", "judge"]
        max_tool_calls = 6
        timeout_s = 300
    elif profile == "adversarial":
        steps = ["secret-scan", "ai-code-scan", "jailbreak-probes", "judge"]
        max_tool_calls = 15
        timeout_s = 600
    else:  # full
        steps = ["secret-scan", "semgrep", "bandit", "sca", "safe-probes", "judge"]
        if mode == "dast":
            steps = ["nuclei", "zap-baseline", "safe-probes", "judge"]
        max_tool_calls = 20
        timeout_s = 900

    return {"mode": mode, "steps": steps, "max_tool_calls": max_tool_calls, "timeout_s": timeout_s, "language": lang}
