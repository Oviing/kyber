"""MCP server: expose the Kyber sandbox to any MCP client (Claude, etc.).

Transport: JSON-RPC 2.0, newline-delimited over stdio (no extra deps).
Launch: `kyber mcp` then point your MCP client at that command.

Tools:
  load_target_snippet(code, language) — provision sandbox, seed /work/target.txt
  load_target_archive(path)           — ship a local .zip into the sandbox, extract there
  sandbox_exec(cmd) / sandbox_ls / sandbox_read
  run_scanner(name) / run_probe(probe_id)
  submit_finding(...) / list_findings() / get_trace()
  start_scan / get_findings passthrough to the HTTP API for persistence.

Safety: every exec passes through policies.is_payload_allowed; only
/work/** and /tmp/** reads; no host mounts (bytes go via exec+base64).
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable, Optional

MCP_VERSION = "2024-11-05"


def _schema(props: dict, required: Optional[list] = None) -> dict:
    return {"type": "object", "properties": props,
            "required": required or [], "additionalProperties": False}


TOOLS: list[dict] = [
    {"name": "load_target_snippet",
     "description": "Provision a fresh sandbox and seed it with source code text.",
     "inputSchema": _schema({"code": {"type": "string"},
                             "language": {"type": "string", "default": "auto"}}, ["code"])},
    {"name": "load_target_archive",
     "description": "Provision a fresh sandbox and extract a local .zip file inside it.",
     "inputSchema": _schema({"path": {"type": "string"}}, ["path"])},
    {"name": "sandbox_exec",
     "description": "Run a shell command inside the isolated sandbox.",
     "inputSchema": _schema({"cmd": {"type": "string"},
                             "timeout": {"type": "integer", "default": 60}}, ["cmd"])},
    {"name": "sandbox_ls",
     "description": "List files under /work in the sandbox.",
     "inputSchema": _schema({"path": {"type": "string", "default": "/work"}})},
    {"name": "sandbox_read",
     "description": "Read a /work/** or /tmp/** file from the sandbox (capped).",
     "inputSchema": _schema({"path": {"type": "string"},
                             "max_bytes": {"type": "integer", "default": 20000}}, ["path"])},
    {"name": "run_scanner",
     "description": "Run secret-scan|semgrep|bandit|trivy|all in the sandbox.",
     "inputSchema": _schema({"name": {"type": "string", "default": "all"}})},
    {"name": "run_probe",
     "description": "Run a safe read-only probe (or 'all').",
     "inputSchema": _schema({"probe_id": {"type": "string", "default": "all"}})},
    {"name": "submit_finding",
     "description": "Record a finding with evidence.",
     "inputSchema": _schema({"rule_id": {"type": "string"}, "title": {"type": "string"},
                             "severity": {"type": "string", "default": "medium"},
                             "location": {"type": "string"},
                             "evidence": {"type": "string"},
                             "confidence": {"type": "string", "default": "medium"}},
                            ["rule_id", "title", "location", "evidence"])},
    {"name": "list_findings",
     "description": "List findings submitted this session.",
     "inputSchema": _schema({})},
    {"name": "get_trace",
     "description": "Return the audit trace of tool calls this session.",
     "inputSchema": _schema({})},
]


class MCPSession:
    def __init__(self) -> None:
        from kyber.agent.tools import AgentToolbox
        from kyber.sandbox.manager import SandboxManager

        self._mgr = SandboxManager()
        self._sandbox: Any = None
        self._toolbox = AgentToolbox(exec_fn=lambda cmd: "(no target loaded)")
        self._target_label = "none"

    def _reset_toolbox(self, exec_fn: Callable[[str], str], label: str) -> None:
        from kyber.agent.tools import AgentToolbox

        old_trace = self._toolbox.trace
        old_sub = self._toolbox.submitted
        self._toolbox = AgentToolbox(exec_fn=exec_fn)
        self._toolbox.trace = old_trace
        self._toolbox.submitted = old_sub
        self._target_label = label

    def _destroy(self) -> None:
        if self._sandbox is not None:
            try:
                self._mgr.destroy(self._sandbox)
            except Exception:
                pass
            self._sandbox = None

    def close(self) -> None:
        self._destroy()

    # -- target loading --
    def load_target_snippet(self, code: str, language: str = "auto") -> dict:
        self._destroy()
        sb = self._mgr.provision("mcp", "static")
        self._sandbox = sb

        def exec_fn(cmd: str) -> str:
            _code, out = self._mgr.exec(sb, cmd, timeout=120)
            return out

        data = (code or "").encode()[:1_000_000]
        try:
            self._mgr.write_file(sb, "/work/target.txt", data)
        except Exception as e:
            return {"ok": False, "error": str(e)[:500]}
        self._reset_toolbox(exec_fn, f"snippet ({language})")
        return {"ok": True, "target": self._target_label}

    def load_target_archive(self, path: str) -> dict:
        from kyber.archive import SANDBOX_EXTRACT_SCRIPT, ArchiveError, load_archive_bytes

        if not path or not os.path.exists(path):
            return {"ok": False, "error": f"no such file: {path!r}"}
        try:
            data = load_archive_bytes(path)
        except OSError as e:
            return {"ok": False, "error": f"cannot read: {e}"}
        self._destroy()
        try:
            sb = self._mgr.provision("mcp", "static")
        except Exception as e:
            return {"ok": False, "error": f"sandbox unavailable: {e}"[:500]}
        self._sandbox = sb

        def exec_fn(cmd: str) -> str:
            _code, out = self._mgr.exec(sb, cmd, timeout=120)
            return out

        try:
            self._mgr.write_bytes_chunked(sb, "/tmp/upload.zip", data)
            self._mgr.write_file(sb, "/tmp/kyber_extract.py",
                                 SANDBOX_EXTRACT_SCRIPT.encode())
            code, listing = self._mgr.exec(sb, "python3 /tmp/kyber_extract.py /tmp/upload.zip /work",
                                           timeout=180)
            if code != 0:
                raise ArchiveError(f"extraction failed: {listing[:500]}")
        except Exception as e:
            return {"ok": False, "error": str(e)[:500]}
        self._reset_toolbox(exec_fn, os.path.basename(path))
        return {"ok": True, "target": self._target_label,
                "members": listing.splitlines()[:20]}

    # -- tools/call dispatch --
    def call(self, name: str, args: dict) -> dict:
        args = args or {}
        try:
            if name == "load_target_snippet":
                res = self.load_target_snippet(args.get("code", ""),
                                               args.get("language", "auto"))
            elif name == "load_target_archive":
                res = self.load_target_archive(args.get("path", ""))
            elif name in ("sandbox_exec", "sandbox_ls", "sandbox_read",
                          "run_scanner", "run_probe", "submit_finding"):
                method = {"sandbox_exec": "sandbox_exec", "sandbox_ls": "sandbox_ls",
                          "sandbox_read": "sandbox_read", "run_scanner": "run_scanner",
                          "run_probe": "run_probe",
                          "submit_finding": "submit_finding"}[name]
                if name == "sandbox_exec":
                    res = self._toolbox.sandbox_exec(args.get("cmd", ""),
                                                     int(args.get("timeout", 60) or 60))
                elif name == "sandbox_ls":
                    res = self._toolbox.sandbox_ls(args.get("path", "/work"))
                elif name == "sandbox_read":
                    res = self._toolbox.sandbox_read(args.get("path", ""),
                                                     int(args.get("max_bytes", 20000) or 20000))
                elif name == "run_scanner":
                    res = self._toolbox.run_scanner(args.get("name", "all"))
                elif name == "run_probe":
                    res = self._toolbox.run_probe(args.get("probe_id", "all"))
                else:
                    res = self._toolbox.submit_finding(args)
                _ = method
            elif name == "list_findings":
                res = self._toolbox.submitted
            elif name == "get_trace":
                res = self._toolbox.trace[-50:]
            else:
                return {"error": f"unknown tool {name!r}"}
            return {"result": res}
        except Exception as e:
            return {"error": str(e)[:1000]}


def _rpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def handle_message(session: MCPSession, msg: dict) -> Optional[dict]:
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        return _rpc_result(req_id, {"protocolVersion": MCP_VERSION,
                                    "capabilities": {"tools": {}},
                                    "serverInfo": {"name": "kyber-sandbox",
                                                   "version": "0.1.0"}})
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return _rpc_result(req_id, {})
    if method == "tools/list":
        return _rpc_result(req_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        out = session.call(name, args)
        if "error" in out:
            return _rpc_result(req_id, {"content": [{"type": "text",
                                                     "text": "error: " + out["error"]}],
                                                    "isError": True})
        return _rpc_result(req_id, {"content": [{"type": "text",
                                                 "text": json.dumps(out["result"])[:8000]}]})
    if method in ("resources/list", "prompts/list"):
        key = "resources" if method.startswith("resources") else "prompts"
        return _rpc_result(req_id, {key: []})
    if req_id is None:
        return None
    return _rpc_error(req_id, -32601, f"method not found: {method}")


def serve_stdio() -> None:
    session = MCPSession()
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                resp = handle_message(session, msg)
            except Exception as e:
                resp = _rpc_error(msg.get("id"), -32603, f"internal: {e}"[:500])
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
    finally:
        session.close()


if __name__ == "__main__":
    serve_stdio()
