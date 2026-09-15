import socket
import subprocess
import sys

import pytest

from kyber import server
from kyber.server import ServerError


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_local_port_from_api():
    assert server.local_port_from_api("http://localhost:8000") == 8000
    assert server.local_port_from_api("http://localhost:9000/x") == 9000
    assert server.local_port_from_api("http://localhost") == 8000
    assert server.local_port_from_api("http://127.0.0.1:1234") == 1234
    assert server.local_port_from_api("http://example.com:8000") is None
    assert server.local_port_from_api("https://example.com") is None


def test_home_pid_log_use_kyber_home(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    assert server.pid_file() == str(tmp_path / "kyber.pid")
    assert server.log_file() == str(tmp_path / "api.log")


def test_read_pid_missing_or_dead(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    assert server.read_pid() is None
    server.write_pid(2147483647)  # cannot exist
    assert server.read_pid() is None


def test_read_pid_live_process(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        server.write_pid(proc.pid)
        assert server.read_pid() == proc.pid
    finally:
        proc.kill()
        proc.wait()


def test_ensure_reuses_healthy(monkeypatch):
    monkeypatch.setattr(server, "is_healthy", lambda api, timeout=3.0: True)
    assert server.ensure_api_up("http://localhost:8000") == "reused"


def test_ensure_no_autostart_errors(monkeypatch):
    monkeypatch.setattr(server, "is_healthy", lambda api, timeout=3.0: False)
    monkeypatch.setattr(server, "read_pid", lambda: None)
    with pytest.raises(ServerError, match="kyber up"):
        server.ensure_api_up("http://localhost:8123", autostart=False)


def test_ensure_remote_errors(monkeypatch):
    monkeypatch.setattr(server, "is_healthy", lambda api, timeout=3.0: False)
    monkeypatch.setattr(server, "read_pid", lambda: None)
    with pytest.raises(ServerError, match="not local"):
        server.ensure_api_up("http://example.com:8000")


def test_ensure_occupied_port_errors(monkeypatch):
    port = _free_port()
    holder = socket.socket()
    holder.bind(("127.0.0.1", port))
    holder.listen(1)
    try:
        monkeypatch.setattr(server, "is_healthy", lambda api, timeout=3.0: False)
        monkeypatch.setattr(server, "read_pid", lambda: None)
        with pytest.raises(ServerError, match="occupied"):
            server.ensure_api_up(f"http://localhost:{port}")
    finally:
        holder.close()


def test_stop_server_none_running(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    assert server.stop_server() == "no managed server running"


def test_stop_server_kills_only_ours(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    server.write_pid(proc.pid)
    assert server.stop_server() == f"stopped server (pid {proc.pid})"
    proc.wait(timeout=10)
    assert proc.returncode is not None
