"""Local (unsafe, container-free) backend tests. No daemon needed."""
import json
import os

import pytest

from kyber.sandbox import local
from kyber.sandbox.common import SandboxError


def test_up_requires_allow_unsafe(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    with pytest.raises(SandboxError, match="--allow-unsafe"):
        local.up("demo")


def test_up_rejects_bad_name(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    with pytest.raises(SandboxError, match="invalid sandbox name"):
        local.up("../evil", allow_unsafe=True)


def test_up_duplicate_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    local.up("demo", allow_unsafe=True)
    with pytest.raises(SandboxError, match="already exists"):
        local.up("demo", allow_unsafe=True)


def test_refuses_root(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    if not hasattr(os, "geteuid"):
        pytest.skip("no geteuid on this platform")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(SandboxError, match="as root"):
        local.up("demo", allow_unsafe=True)


def test_exec_roundtrip_and_env_scrub(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    monkeypatch.setenv("KYBER_TEST_SECRET", "super-secret-123")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/fake.sock")
    info = local.up("demo", allow_unsafe=True)
    assert info.backend == "local"
    code, out = local.exec_cmd("demo", "pwd && env", allow_unsafe=True)
    assert code == 0
    assert str(tmp_path / "workspaces" / "demo") in out
    assert "KYBER_TEST_SECRET" not in out
    assert "super-secret-123" not in out
    assert "SSH_AUTH_SOCK" not in out
    # HOME is jailed to the workspace.
    code, out = local.exec_cmd("demo", "echo HOME=$HOME", allow_unsafe=True)
    assert f"HOME={info.volume}" in out


def test_exec_exit_code_and_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    local.up("demo", allow_unsafe=True)
    code, _ = local.exec_cmd("demo", "exit 3", allow_unsafe=True)
    assert code == 3
    code, out = local.exec_cmd("demo", "sleep 10", timeout=1, allow_unsafe=True)
    assert code == 124
    assert "timed out" in out


def test_exec_missing_session(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    with pytest.raises(SandboxError, match="not found"):
        local.exec_cmd("ghost", "ls", allow_unsafe=True)


def test_offline_up_fails_fast_without_working_seatbelt(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    monkeypatch.setattr(local, "seatbelt_usable", lambda timeout=10: False)
    with pytest.raises(SandboxError, match="cannot be enforced"):
        local.up("demo", offline=True, allow_unsafe=True)
    # No half-created session left behind.
    assert not local.session_exists("demo")


def test_offline_exec_refused_without_enforcement(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    monkeypatch.setattr(local.shutil, "which", lambda _: None)
    # Legacy/tampered record claiming offline without enforcement proof.
    ws = local.workspace_dir("demo")
    os.makedirs(ws, exist_ok=True)
    store = {**json.loads("{}"), "demo": {"backend": "local", "workspace": ws,
                                          "offline": True, "offline_enforced": False}}
    with open(tmp_path / "sandboxes.json", "w", encoding="utf-8") as fh:
        json.dump(store, fh)
    with pytest.raises(SandboxError, match="cannot be enforced"):
        local.exec_cmd("demo", "echo hi", allow_unsafe=True)


def test_offline_enforced_when_seatbelt_works(tmp_path, monkeypatch):
    if not local.seatbelt_usable():
        pytest.skip("no working sandbox-exec on this machine")
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    local.up("demo", offline=True, allow_unsafe=True)
    code, out = local.exec_cmd("demo", "echo hi-offline", allow_unsafe=True)
    assert code == 0
    assert "hi-offline" in out


def test_snapshot_and_down(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    local.up("demo", allow_unsafe=True)
    local.exec_cmd("demo", "echo data > hello.txt", allow_unsafe=True)
    import tarfile

    out = str(tmp_path / "ws.tar")
    path = local.snapshot("demo", out)
    with tarfile.open(path) as tf:
        names = tf.getnames()
    assert any("hello.txt" in n for n in names)
    msg = local.down("demo")
    assert "workspace kept" in msg
    assert (tmp_path / "workspaces" / "demo").is_dir()
    assert json.loads((tmp_path / "sandboxes.json").read_text()) == {}
    local.up("demo2", allow_unsafe=True)
    local.down("demo2", keep_volume=False)
    assert not (tmp_path / "workspaces" / "demo2").exists()


def test_list_sessions(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    local.up("b-one", allow_unsafe=True)
    local.up("a-two", allow_unsafe=True)
    names = [s.name for s in local.list_sessions()]
    assert names == ["a-two", "b-one"]
    assert all(s.backend == "local" for s in local.list_sessions())


def test_interactive_spec_jails_cwd_and_home(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    monkeypatch.setenv("KYBER_TEST_SECRET", "zzz")
    local.up("demo", allow_unsafe=True)
    argv, cwd, env = local.interactive_spec("demo", allow_unsafe=True)
    assert cwd == str(tmp_path / "workspaces" / "demo")
    assert env["HOME"] == cwd
    assert "KYBER_TEST_SECRET" not in env
    assert argv and argv[0].startswith("/")
