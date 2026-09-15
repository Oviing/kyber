from kyber.agents.judge import judge, to_sarif


def test_judge_dedupes_and_sorts():
    raw = [
        {"rule_id": "a", "title": "t", "severity": "low", "location": "f:1", "evidence": "e", "tool": "x"},
        {"rule_id": "a", "title": "t", "severity": "high", "location": "f:1", "evidence": "e", "tool": "x"},
        {"rule_id": "", "title": "", "severity": "high"},
        {"rule_id": "b", "title": "t2", "severity": "medium", "location": "g:2", "evidence": "e2", "tool": "x"},
    ]
    out = judge(raw)
    assert len(out) == 2
    assert out[0]["severity"] == "high"


def test_sarif_shape():
    s = to_sarif([{"rule_id": "r", "title": "t", "severity": "high", "location": "f:1"}], "scan1")
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["results"][0]["ruleId"] == "r"
