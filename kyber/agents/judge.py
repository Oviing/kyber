"""Judge: dedupe, require evidence, normalize severity. Drops hallucinations."""
from collections import OrderedDict

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def normalize(f: dict) -> dict:
    f = dict(f)
    f["severity"] = (f.get("severity") or "medium").lower()
    if f["severity"] not in SEVERITY_ORDER:
        f["severity"] = "medium"
    f["confidence"] = (f.get("confidence") or "medium").lower()
    if f.get("evidence"):
        f["evidence"] = str(f["evidence"])[:2000]
    return f


def judge(raw: list[dict]) -> list[dict]:
    seen: OrderedDict[tuple, dict] = OrderedDict()
    for f in raw:
        # Require rule_id + title + some evidence or tool trace; drop empty hallucinations.
        if not f.get("rule_id") or not f.get("title"):
            continue
        if not f.get("evidence") and not f.get("location"):
            continue
        n = normalize(f)
        key = (n["rule_id"], n.get("location"), (n.get("evidence") or "")[:120])
        if key not in seen:
            seen[key] = n
        else:
            # Keep higher severity on duplicates.
            if SEVERITY_ORDER[n["severity"]] > SEVERITY_ORDER[seen[key]["severity"]]:
                seen[key] = n
    return sorted(seen.values(), key=lambda x: SEVERITY_ORDER[x["severity"]], reverse=True)


def to_sarif(findings: list[dict], scan_id: str) -> dict:
    rules = []
    results = []
    for f in findings:
        rules.append({"id": f["rule_id"], "name": f["title"]})
        results.append(
            {
                "ruleId": f["rule_id"],
                "level": "error" if f["severity"] in ("critical", "high") else "warning",
                "message": {"text": f["title"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("location", "?")}}}],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "kyber", "rules": rules}}, "results": results,
                  "automationDetails": {"id": scan_id}}],
    }
