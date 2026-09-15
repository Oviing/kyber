"""Detection matrix: CLI-present vs daemon-reachable are different states."""
import subprocess
import sys
import types

from kyber import onboard
from kyber.sandbox import docker_env


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _no_docker_pkg(monkeypatch):
    monkeypatch.setitem(sys.modules, "docker", None)


def _ping_result(monkeypatch, ok: bool):
    mod = types.ModuleType("docker")

    class FakeClient:
        def ping(self):
            if not ok:
                raise OSError("connection refused")

    mod.from_env = lambda timeout=None, **k: FakeClient()
    monkeypatch.setitem(sys.modules, "docker", mod)


def test_daemon_cli_missing(monkeypatch):
    monkeypatch.setattr(docker_env.shutil, "which", lambda _: None)
    ok, detail = docker_env.daemon_reachable()
    assert ok is False
    assert "CLI not found" in detail


def test_daemon_reachable_via_python_ping(monkeypatch):
    monkeypatch.setattr(docker_env.shutil, "which", lambda _: "/usr/bin/docker")
    _ping_result(monkeypatch, True)
    ok, _detail = docker_env.daemon_reachable()
    assert ok is True


def test_daemon_reachable_via_cli_fallback(monkeypatch):
    monkeypatch.setattr(docker_env.shutil, "which", lambda _: "/usr/bin/docker")
    _no_docker_pkg(monkeypatch)
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: FakeCompleted(0, stdout="27.0.0\n"))
    ok, detail = docker_env.daemon_reachable()
    assert ok is True
    assert "27.0.0" in detail


def test_daemon_unreachable_keeps_error_tail_and_retry_hint(monkeypatch):
    monkeypatch.setattr(docker_env.shutil, "which", lambda _: "/usr/bin/docker")
    _ping_result(monkeypatch, False)
    err = ("Cannot connect to the Docker daemon at "
           "unix:///Users/joel/.docker/run/docker.sock. "
           "Is the docker daemon running?")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: FakeCompleted(1, stderr=err))
    monkeypatch.setenv("DOCKER_HOST", "")
    ok, detail = docker_env.daemon_reachable()
    assert ok is False
    assert "Is the docker daemon running" in detail
    assert "socket" in detail or "unix://" in detail
    assert "--backend local" in detail


def test_onboard_daemon_status_no_cli(monkeypatch):
    monkeypatch.setattr(docker_env.shutil, "which", lambda _: None)
    ok, detail = onboard.docker_daemon_status()
    assert ok is False
    assert "CLI not found" in detail


def test_onboard_image_status_daemon_down_does_not_say_query_failed(monkeypatch):
    monkeypatch.setattr(docker_env, "daemon_reachable",
                        lambda timeout=10: (False, "docker daemon unreachable at unix:///x"))
    ok, detail = onboard.sandbox_image_status()
    assert ok is None
    assert "query failed" not in detail
    assert "daemon" in detail


def test_onboard_image_present_and_missing(monkeypatch):
    monkeypatch.setattr(docker_env, "daemon_reachable",
                        lambda timeout=10: (True, "docker daemon reachable"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompleted(
        0, stdout="kyber-sandbox:latest\nother:1\n"))
    ok, detail = onboard.sandbox_image_status()
    assert ok is True
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: FakeCompleted(0, stdout="other:1\n"))
    ok, detail = onboard.sandbox_image_status()
    assert ok is False
    assert "missing sandbox image" in detail


def test_socket_hint_respects_docker_host(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "ssh://builder@10.0.0.5")
    assert docker_env.socket_hint() == "ssh://builder@10.0.0.5"


def test_onboard_identity_status_branches(monkeypatch):
    from kyber import onboard
    from kyber.sandbox import shell as shell_mod

    monkeypatch.setattr(shell_mod, "image_identity_present", lambda tag="x": True)
    ok, _ = onboard.sandbox_identity_status()
    assert ok is True
    monkeypatch.setattr(shell_mod, "image_identity_present", lambda tag="x": False)
    monkeypatch.setattr(onboard, "docker_daemon_status", lambda timeout=5: (True, "up"))
    ok, detail = onboard.sandbox_identity_status()
    assert ok is False
    assert "build" in detail
