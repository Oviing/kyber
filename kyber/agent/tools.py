"""Shared tool layer for LLM agents (CLI `kyber agent` + MCP server + API).

Every tool executes inside the sandbox via SandboxManager (or a stub exec_fn
in tests / no-Docker fallback). All commands pass through
policies.is_payload_allowed; output is truncated; every call is logged to an
in-memory trace for the LLM loop and for audit artifacts.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from kyber.sandbox import policies
from kyber.tools.safe_probes import PROBES

OUTPUT_LIMIT = 8000
READ_LIMIT = 20000

SCANNER_COMMANDS = {
    "secret-scan": "gitleaks detect --no-git -v /work 2>/dev/null || true",
    "semgrep": "semgrep --config auto --json --quiet /work 2>/dev/null || true",
    "bandit": "bandit -r /work -f json -q 2>/dev/null || true",
    "trivy": "trivy fs --format json --quiet /work 2>/dev/null || true",
}

TOOL_SPECS = [
    {"name": "sandbox_exec",
     "description": "Run a shell command inside the isolated sandbox. Blocked payloads are rejected.",
     "args": {"cmd": "string (required)", "timeout": "int seconds, default 60"}},
    {"name": "sandbox_ls",
     "description": "List files under /work (extracted target tree).",
     "args": {"path": "string, default /work"}},
    {"name": "sandbox_read",
     "description": "Read a file from inside the sandbox (capped).",
     "args": {"path": "string (required)", "max_bytes": "int, default 20000"}},
    {"name": "run_scanner",
     "description": "Run a named scanner (secret-scan, semgrep, bandit, trivy) and return parsed findings.",
     "args": {"name": "string (required)"}},
    {"name": "run_probe",
     "description": "Run a safe read-only probe (sqli/sleep, xss/reflected, cmdi/marker, traversal/marker, ssrf/metadata) or 'all'.",
     "args": {"probe_id": "string, default all", "target": "string for URL targets"}},
    {"name": "submit_finding",
     "description": "Record a finding with evidence. Requires rule_id, title, location, evidence.",
     "args": {"rule_id": "str", "title": "str", "severity": "critical|high|medium|low|info",
              "location": "str", "evidence": "str", "confidence": "str, default medium"}},
]


@dataclass
class AgentToolbox:
    """Callable tools bound to one sandbox (or stub) execution."""

    exec_fn: Callable[[str], str]
    target_type: str = "snippet"
    service_url: str = ""
    archive_name: str = "target"
    max_tool_calls: int = 25
    trace: list[dict[str, Any]] = field(default_factory=list)
    submitted: list[dict[str, Any]] = field(default_factory=list)
    calls: int = 0

    def _log(self, tool: str, args: dict, result_preview: str) -> None:
        self.trace.append({"tool": tool, "args": args,
                           "result_preview": result_preview[:2000]})

    def _guard(self) -> None:
        self.calls += 1
        if self.calls > self.max_tool_calls:
            raise RuntimeError("max tool calls exceeded")

    def _safe_path(self, path: str) -> Optional[str]:
        p = (path or "").strip()
        if not p.startswith("/work") and not p.startswith("/tmp/"):
            return None
        if ".." in p.split("/"):
            return None
        return p

    def sandbox_exec(self, cmd: str, timeout: int = 60) -> str:
        self._guard()
        if not policies.is_payload_allowed(cmd or ""):
            out = "BLOCKED by sandbox policy (forbidden payload)."
            self._log("sandbox_exec", {"cmd": (cmd or "")[:300]}, out)
            return out
        try:
            out = self.exec_fn(cmd) or ""
        except Exception as e:
            out = f"tool error: {e}"[:1000]
        self._log("sandbox_exec", {"cmd": (cmd or "")[:300]}, out[:2000])
        return out[:OUTPUT_LIMIT]

    def sandbox_ls(self, path: str = "/work") -> str:
        self._guard()
        safe = self._safe_path(path) or "/work"
        try:
            out = self.exec_fn(f"ls -la {shlex.quote(safe)} 2>&1 || find /work -maxdepth 3 -type f | head -100")
        except Exception as e:
            out = f"tool error: {e}"[:1000]
        self._log("sandbox_ls", {"path": safe}, out[:2000])
        return (out or "")[:OUTPUT_LIMIT]

    def sandbox_read(self, path: str, max_bytes: int = READ_LIMIT) -> str:
        self._guard()
        safe = self._safe_path(path)
        if not safe:
            out = "BLOCKED: only /work/** and /tmp/** reads are allowed."
            self._log("sandbox_read", {"path": path}, out)
            return out
        cap = max(1, min(int(max_bytes or READ_LIMIT), READ_LIMIT))
        try:
            out = self.exec_fn(f"head -c {cap} {shlex.quote(safe)} 2>&1")
        except Exception as e:
            out = f"tool error: {e}"[:1000]
        self._log("sandbox_read", {"path": safe}, out[:2000])
        return (out or "")[:cap]

    def run_scanner(self, name: str) -> list[dict]:
        from kyber.tools import scanners
        from kyber.tools.safe_probes import static_secret_scan

        self._guard()
        name = (name or "").strip().lower()
        if name not in SCANNER_COMMANDS and name != "all":
            out: Any = {"error": f"unknown scanner {name!r}; choose from "
                                 f"{sorted(SCANNER_COMMANDS)} or 'all'"}
            self._log("run_scanner", {"name": name}, str(out)[:500])
            return [self._wrap_tool_error("scanner", str(out))]
        names = sorted(SCANNER_COMMANDS) if name == "all" else [name]
        findings: list[dict] = []
        for n in names:
            cmd = SCANNER_COMMANDS[n]
            if not policies.is_payload_allowed(cmd):
                continue
            try:
                raw = self.exec_fn(cmd) or ""
            except Exception as e:
                findings.append(self._wrap_tool_error(n, str(e)[:500]))
                continue
            if n == "secret-scan":
                # gitleaks output is noisy; also run the regex fallback on nothing?
                # Keep raw hint only if it mentions leaks.
                if "leak" in raw.lower() or "secret" in raw.lower():
                    findings.append({"rule_id": "secret/gitleaks-hit",
                                     "title": "Possible secret reported by gitleaks",
                                     "severity": "medium", "confidence": "low",
                                     "location": "/work", "evidence": raw[:2000],
                                     "tool": "gitleaks"})
            elif "semgrep" in cmd:
                findings.extend(scanners.parse_semgrep(raw))
            elif "bandit" in cmd:
                findings.extend(scanners.parse_bandit(raw))
            elif "trivy" in cmd and ("VULNERABILITY" in raw.upper() or "CVE-" in raw):
                findings.append({"rule_id": "sca/vuln-deps",
                                 "title": "Vulnerable dependencies detected",
                                 "severity": "high", "confidence": "medium",
                                 "location": "deps", "evidence": raw[:2000],
                                 "tool": "trivy"})
        # Fallback: if scanners are absent in the sandbox (empty output),
        # surface nothing here — static secret regex already ran in jobs.py.
        _ = static_secret_scan  # keep import for future direct-text fallback
        self._log("run_scanner", {"name": name}, f"{len(findings)} finding(s)")
        return findings

    def run_probe(self, probe_id: str = "all", target: str = "") -> list[dict]:
        from kyber.agents import exploiter

        self._guard()
        url = target or self.service_url
        # Probes score live HTTP responses; scoring the payload string itself
        # would be a guaranteed false positive, so they only run against an
        # explicit live URL (API url targets already require consent_owned).
        if not url or (self.target_type != "url" and not target):
            self._log("run_probe", {"probe_id": probe_id},
                      "skipped: probes need a live url target with consent")
            return []
        loc = url
        ids = [probe_id] if probe_id != "all" else [p["id"] for p in PROBES]
        out: list[dict] = []
        for pid in ids:
            probe = next((p for p in PROBES if p["id"] == pid), None)
            if not probe:
                continue
            for payload in probe["payloads"][:2]:
                try:
                    resp = self.exec_fn(
                        f"curl -s -m 8 '{url}' --get "
                        f"--data-urlencode 'q={payload}' || true")
                    f = exploiter.score_probe_response(pid, resp or "", loc)
                    if f:
                        out.append(f)
                except Exception:
                    continue
        self._log("run_probe", {"probe_id": probe_id}, f"{len(out)} finding(s)")
        return out

    def submit_finding(self, finding: dict) -> dict:
        self._guard()
        f = dict(finding or {})
        missing = [k for k in ("rule_id", "title", "location", "evidence") if not f.get(k)]
        if missing:
            res = {"ok": False, "error": f"missing fields: {missing}"}
            self._log("submit_finding", {"rule_id": f.get("rule_id")}, str(res))
            return res
        f.setdefault("severity", "medium")
        f.setdefault("confidence", "medium")
        f.setdefault("tool", "agent")
        self.submitted.append(f)
        res = {"ok": True, "count": len(self.submitted)}
        self._log("submit_finding", {"rule_id": f.get("rule_id")}, str(res))
        return res

    def _wrap_tool_error(self, tool: str, err: str) -> dict:
        return {"rule_id": "infra/tool-error", "title": f"Scanner tool failed: {tool}",
                "severity": "info", "confidence": "low", "location": "scanner",
                "evidence": err[:500], "tool": tool}

    def dispatch(self, tool: str, args: dict) -> Any:
        args = dict(args or {})
        if tool == "sandbox_exec":
            return self.sandbox_exec(args.get("cmd", ""), int(args.get("timeout", 60) or 60))
        if tool == "sandbox_ls":
            return self.sandbox_ls(args.get("path", "/work"))
        if tool == "sandbox_read":
            return self.sandbox_read(args.get("path", ""),
                                     int(args.get("max_bytes", READ_LIMIT) or READ_LIMIT))
        if tool == "run_scanner":
            return self.run_scanner(args.get("name", ""))
        if tool == "run_probe":
            return self.run_probe(args.get("probe_id", "all"), args.get("target", ""))
        if tool == "submit_finding":
            return self.submit_finding(args)
        raise ValueError(f"unknown tool {tool!r}")
