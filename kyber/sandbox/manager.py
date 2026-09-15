"""Docker-backed sandbox manager. One isolated network + containers per scan."""
from __future__ import annotations

import time
import uuid
from typing import Optional

from kyber.sandbox import policies
from kyber.sandbox.policies import DEFAULT_LIMITS


class SandboxError(RuntimeError):
    pass


class Sandbox:
    """Handle to a provisioned sandbox (network + containers)."""

    def __init__(self, scan_id: str, network_name: str, containers: list, client=None):
        self.scan_id = scan_id
        self.network_name = network_name
        self.containers = containers
        self.client = client

    @property
    def primary(self):
        return self.containers[0] if self.containers else None


class SandboxManager:
    def __init__(self, client=None):
        self._client = client  # lazy docker import for testability

    def _docker(self):
        if self._client is not None:
            return self._client
        import docker

        return docker.from_env()

    def provision(self, scan_id: str, mode: str = "static") -> Sandbox:
        """Create isolated network + attacker container. Target container added for dast mode."""
        client = self._docker()
        net_name = f"kyber-{scan_id[:8]}-{uuid.uuid4().hex[:6]}"
        client.networks.create(net_name, driver="bridge", internal=(mode == "static"))
        containers = []
        try:
            kw = policies.container_kwargs(
                "kyber-attacker:latest", f"kyber-{scan_id[:8]}-attacker", net_name, DEFAULT_LIMITS
            )
            attacker = client.containers.run(**kw, command="sleep 3600")
            containers.append(attacker)
            if mode == "dast":
                kw2 = policies.container_kwargs(
                    "kyber-target-py:latest", f"kyber-{scan_id[:8]}-target", net_name, DEFAULT_LIMITS
                )
                target = client.containers.run(**kw2, command="sleep 3600")
                containers.append(target)
        except Exception as e:
            self.destroy(Sandbox(scan_id, net_name, containers, client))
            raise SandboxError(f"provision failed: {e}") from e
        return Sandbox(scan_id, net_name, containers, client)

    def exec(self, sandbox: Sandbox, cmd: str, timeout: int = 60) -> tuple[int, str]:
        if not policies.is_payload_allowed(cmd):
            raise SandboxError("forbidden payload blocked by policy")
        if sandbox.primary is None:
            raise SandboxError("no container in sandbox")
        result = sandbox.primary.exec_run(cmd, demux=False)
        # docker-py returns ExecResult(exit_code, output)
        code, out = result.exit_code, result.output
        text = out.decode("utf-8", errors="replace") if isinstance(out, (bytes, bytearray)) else str(out)
        return code, text[:20000]

    def write_file(self, sandbox: Sandbox, path: str, content: bytes) -> None:
        """Write untrusted code into sandbox via exec + heredoc (avoids host mounts)."""
        if len(content) > policies.MAX_SNIPPET_BYTES:
            raise SandboxError("snippet too large")
        import base64

        b64 = base64.b64encode(content).decode()
        # Decode inside container to a writable tmp path.
        self.exec(sandbox, f"sh -c 'echo {b64} | base64 -d > {path}'", timeout=30)

    def write_bytes_chunked(self, sandbox: Sandbox, path: str, content: bytes,
                              max_total: int = 50 * 1024 * 1024, chunk_chars: int = 200_000) -> None:
        """Write large untrusted bytes into the sandbox via chunked base64 appends.

        Avoids host mounts and single-command ARG_MAX limits. Caller must have
        validated content (e.g. kyber.archive guards).
        """
        if len(content) > max_total:
            raise SandboxError(f"content too large ({len(content)} bytes, max {max_total})")
        import base64

        b64 = base64.b64encode(content).decode()
        self.exec(sandbox, f"sh -c 'echo -n > {path}'", timeout=30)
        for i in range(0, len(b64), chunk_chars):
            piece = b64[i:i + chunk_chars]
            self.exec(sandbox, f"sh -c 'echo -n {piece} >> {path}.b64'", timeout=30)
        self.exec(sandbox, f"sh -c 'base64 -d {path}.b64 > {path} && rm {path}.b64'", timeout=120)

    def destroy(self, sandbox: Sandbox) -> None:
        for c in sandbox.containers:
            try:
                c.remove(force=True)
            except Exception:
                pass
        try:
            if sandbox.client is not None:
                net = sandbox.client.networks.get(sandbox.network_name)
                net.remove()
        except Exception:
            pass

    def run_with_cleanup(self, scan_id: str, mode: str, fn, timeout_s: Optional[int] = None):
        timeout_s = timeout_s or 300
        sb = self.provision(scan_id, mode)
        started = time.time()
        try:
            if time.time() - started > timeout_s:
                raise SandboxError("sandbox timeout")
            return fn(sb)
        finally:
            self.destroy(sb)
