"""Dispatcher: auto/docker/local routing + cross-backend collisions."""
import pytest

from kyber.sandbox import backends, docker_env, local
from kyber.sandbox.common import SandboxError


@pytest.fixture(autouse=True)
def _no_real_docker(monkeypatch):
    """Isolate from any real daemon/containers on the dev machine."""
    monkeypatch.setattr(backends, "_docker_has", lambda name: False)


def test_resolve_explicit():
    assert backends.resolve("docker") == "docker"
    assert backends.resolve("local") == "local"
    with pytest.raises(SandboxError, match="invalid backend"):
        backends.resolve("lxc")


def test_resolve_auto_prefers_docker(monkeypatch):
    monkeypatch.setattr(docker_env, "daemon_reachable",
                        lambda timeout=5: (True, "daemon reachable"))
    assert backends.resolve("auto") == "docker"


def test_resolve_auto_without_daemon_names_local_retry(monkeypatch):
    monkeypatch.setattr(docker_env, "daemon_reachable",
                        lambda timeout=5: (False, "docker daemon unreachable at unix:///x"))
    with pytest.raises(SandboxError, match="--backend local --allow-unsafe"):
        backends.resolve("auto", name="demo")


def test_up_local_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    info = backends.up("demo", backend="local", allow_unsafe=True)
    assert info.backend == "local"
    code, out = backends.exec_cmd("demo", "echo via-dispatcher", backend="auto",
                                  allow_unsafe=True)
    assert code == 0
    assert "via-dispatcher" in out


def test_up_local_needs_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    with pytest.raises(SandboxError, match="--allow-unsafe"):
        backends.up("demo", backend="local")


def test_docker_up_refused_when_local_owns_name(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    local.up("demo", allow_unsafe=True)
    with pytest.raises(SandboxError, match="local backend"):
        backends.up("demo", backend="docker")


def test_local_up_refused_when_docker_owns_name(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    monkeypatch.setattr(backends, "_docker_has", lambda name: True)
    with pytest.raises(SandboxError, match="docker backend"):
        backends.up("demo", backend="local", allow_unsafe=True)


def test_read_auto_prefers_local_store_without_daemon(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    local.up("demo", allow_unsafe=True)
    monkeypatch.setattr(docker_env, "daemon_reachable",
                        lambda timeout=5: (False, "down"))
    assert backends._read_backend("demo", "auto") == "local"


def test_list_all_merges_backends(tmp_path, monkeypatch):
    from kyber.sandbox import shell as shell_mod

    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    local.up("zz-local", allow_unsafe=True)
    monkeypatch.setattr(shell_mod, "list_sessions", lambda client=None: [])
    names = [(s.backend, s.name) for s in backends.list_all("auto")]
    assert ("local", "zz-local") in names


def test_up_mount_rejected_for_local_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    with pytest.raises(SandboxError, match="--mount is a docker-backend option"):
        backends.up("demo", backend="local", allow_unsafe=True, mount=str(tmp_path))


def test_up_mount_passes_through_to_docker(monkeypatch, tmp_path):
    from kyber.sandbox import shell as shell_mod

    ws = tmp_path / "proj"
    ws.mkdir()
    seen = {}

    def fake_up(name, **kwargs):
        seen.update(kwargs)
        from kyber.sandbox.common import SandboxInfo
        return SandboxInfo(name=name, container="c", network="n",
                           volume=kwargs.get("host_mount") or "v", image="i")

    monkeypatch.setattr(shell_mod, "up", fake_up)
    backends.up("demo", backend="docker", mount=str(ws))
    assert seen.get("host_mount") == str(ws)


def test_up_with_tools_selects_flavor_and_strips_key(tmp_path, monkeypatch):
    from kyber.sandbox import shell as shell_mod
    from kyber.sandbox import tools as tools_mod

    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-stale")
    tools_mod.grant_consent(tools_mod.load_manifest("claude"))
    monkeypatch.setattr(shell_mod, "image_present", lambda tag, client=None: True)
    seen = {}

    def fake_up(name, **kwargs):
        seen.update(kwargs)
        from kyber.sandbox.common import SandboxInfo
        return SandboxInfo(name=name, container="c", network="n",
                           volume="v", image=kwargs["image"], backend="docker")

    monkeypatch.setattr(shell_mod, "up", fake_up)
    info = backends.up("demo", backend="docker", tools=["claude"], subscription=True)
    assert info.image == "kyber-sandbox:with-claude"
    assert seen["env"].get("CLAUDE_CODE_OAUTH_TOKEN") == "tok"
    assert "ANTHROPIC_API_KEY" not in seen["env"]


def test_up_with_tools_missing_flavor_hints_build(tmp_path, monkeypatch):
    from kyber.sandbox import shell as shell_mod
    from kyber.sandbox import tools as tools_mod

    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    tools_mod.grant_consent(tools_mod.load_manifest("claude"))
    monkeypatch.setattr(shell_mod, "image_present", lambda tag, client=None: False)
    with pytest.raises(SandboxError, match="build --with claude"):
        backends.up("demo", backend="docker", tools=["claude"])


def test_up_with_tools_needs_consent(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    with pytest.raises(SandboxError, match="needs consent"):
        backends.up("demo", backend="docker", tools=["codex"])


def test_up_local_stores_auth_keys_and_subscription(tmp_path, monkeypatch):
    from kyber.sandbox import tools as tools_mod

    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    tools_mod.grant_consent(tools_mod.load_manifest("claude"))
    info = backends.up("demo", backend="local", allow_unsafe=True,
                       tools=["claude"], subscription=True)
    assert info.backend == "local"
    import json as _json

    rec = _json.loads((tmp_path / "sandboxes.json").read_text())["demo"]
    assert rec["auth_keys"] == ["CLAUDE_CODE_OAUTH_TOKEN"]
    assert rec["subscription"] is True
