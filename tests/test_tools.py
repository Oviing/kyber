"""Tool flavors: manifests, flavor tags, auth resolution, consent, conflicts."""
import json
import os

import pytest

from kyber.sandbox import tools as tools_mod
from kyber.sandbox.common import SandboxError


def test_builtin_manifests_load():
    ids = tools_mod.available_ids()
    for expected in ("claude", "codex", "opencode", "gemini"):
        assert expected in ids, ids
    m = tools_mod.load_manifest("claude")
    assert m.auth_env == ("CLAUDE_CODE_OAUTH_TOKEN",)
    assert m.auth_files == ()
    codex = tools_mod.load_manifest("codex")
    assert len(codex.auth_files) == 1
    assert codex.auth_files[0].mode == "rw"
    assert codex.auth_files[0].dest == "/home/sandbox/.codex/auth.json"


def test_unknown_tool_lists_available():
    with pytest.raises(SandboxError, match="Available:"):
        tools_mod.load_manifest("nope")


def test_user_manifest_overrides_and_example(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    d = tools_mod.ensure_user_dir()
    assert os.path.isdir(d)
    example = os.path.join(d, "acme-coder.yaml.example")
    assert os.path.isfile(example)  # template only, not loadable
    assert "acme-coder" not in tools_mod.available_ids()
    mine = os.path.join(d, "acme.yaml")
    with open(mine, "w", encoding="utf-8") as fh:
        fh.write("""\
schema: kyber-tool/v1
id: acme
display: Acme
description: x
install: ["echo hi"]
dirs: [/home/sandbox/.acme]
check: acme --version
auth:
  env: [ACME_API_KEY]
  files: []
""")
    assert "acme" in tools_mod.available_ids()
    assert tools_mod.load_manifest("acme").source == "user"


def test_bad_manifests_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    d = tools_mod.ensure_user_dir()

    def write(name, body):
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body)
        return p

    write("bad.yaml", "schema: kyber-tool/v1\nid: bad\ndisplay: x\n")
    with pytest.raises(SandboxError, match="install"):
        tools_mod.load_manifest("bad")
    os.remove(os.path.join(d, "bad.yaml"))

    write("evil.yaml", """\
schema: kyber-tool/v1
id: evil
display: x
description: x
install: ["echo hi"]
dirs: [/home/sandbox/.evil]
check: evil --version
auth:
  env: []
  files: [{src: ~/.ssh/id_rsa, dest: /home/sandbox/.ssh/id_rsa, mode: ro}]
""")
    m = tools_mod.load_manifest("evil")  # parses; resolve flags nothing yet
    assert m.auth_files[0].src.endswith(".ssh/id_rsa")
    # ...but a dest hiding the workspace is rejected at parse time:
    write("evil2.yaml", """\
schema: kyber-tool/v1
id: evil2
display: x
description: x
install: ["echo hi"]
dirs: [/home/sandbox/.evil]
check: evil --version
auth:
  env: []
  files: [{src: /tmp/a.json, dest: /work/evil.json, mode: ro}]
""")
    with pytest.raises(SandboxError, match="/work"):
        tools_mod.load_manifest("evil2")


def test_parse_id_list():
    assert tools_mod.parse_id_list("claude, codex;opencode ,,") == ["claude", "codex", "opencode"]
    assert tools_mod.parse_id_list("") == []
    with pytest.raises(SandboxError, match="invalid tool id"):
        tools_mod.parse_id_list("a/b")


def test_flavor_tag_deterministic():
    assert tools_mod.flavor_tag(["codex", "claude"]) == tools_mod.flavor_tag(["claude", "codex"])
    tag = tools_mod.flavor_tag(["claude", "codex"])
    assert tag == "kyber-sandbox:with-claude-codex"
    long_tag = tools_mod.flavor_tag(["a" * 30, "b" * 30])
    assert len(long_tag) < 80


def test_flavor_dockerfile_content():
    df = tools_mod.flavor_dockerfile(["opencode"], "kyber-sandbox:latest")
    assert df.startswith("FROM kyber-sandbox:latest")
    assert "npm install -g opencode-ai" in df
    assert "chown -R 65532:65532 /home/sandbox" in df
    assert "USER 65532" in df
    assert 'LABEL kyber.identity="1"' in df


def test_resolve_auth_env_and_missing(monkeypatch):
    got = tools_mod.resolve_auth(["claude"], host_env={})
    assert got.env == {}
    assert any("CLAUDE_CODE_OAUTH_TOKEN" in m for m in got.missing)
    got2 = tools_mod.resolve_auth(["claude"], host_env={"CLAUDE_CODE_OAUTH_TOKEN": "tok"})
    assert got2.env == {"CLAUDE_CODE_OAUTH_TOKEN": "tok"}


def test_resolve_auth_files(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    d = tools_mod.ensure_user_dir()
    cred = tmp_path / "auth.json"
    cred.write_text("{}")
    with open(os.path.join(d, "demo.yaml"), "w", encoding="utf-8") as fh:
        fh.write(f"""\
schema: kyber-tool/v1
id: demo
display: Demo
description: x
install: ["echo hi"]
dirs: [/home/sandbox/.demo]
check: demo --version
auth:
  env: []
  files:
    - src: {cred}
      dest: /home/sandbox/.demo/auth.json
      mode: ro
""")
    got = tools_mod.resolve_auth(["demo"])
    assert got.mounts == [{"src": str(cred), "dest": "/home/sandbox/.demo/auth.json",
                           "mode": "ro", "tool": "demo"}]
    assert got.missing == []
    os.remove(str(cred))
    got2 = tools_mod.resolve_auth(["demo"])
    assert got2.mounts == []
    assert any("auth.json" in m for m in got2.missing)


def test_consent_roundtrip_and_fingerprint(tmp_path, monkeypatch):
    monkeypatch.setenv("KYBER_HOME", str(tmp_path))
    m = tools_mod.load_manifest("opencode")
    assert not tools_mod.is_consented(m)
    tools_mod.grant_consent(m)
    assert tools_mod.is_consented(m)
    assert tools_mod.revoke_consent("opencode") is True
    assert not tools_mod.is_consented(m)
    assert tools_mod.revoke_consent("opencode") is False
    store = json.loads((tmp_path / "consent.json").read_text())
    assert "opencode" not in store


def test_consent_report_names_files():
    report = tools_mod.consent_report("codex")
    assert ".codex/auth.json" in report
    assert "[rw]" in report


def test_subscription_conflict():
    assert tools_mod.subscription_conflict({}) is None
    assert tools_mod.subscription_conflict({"ANTHROPIC_API_KEY": "x"}) is None
    msg = tools_mod.subscription_conflict(
        {"ANTHROPIC_API_KEY": "x", "CLAUDE_CODE_OAUTH_TOKEN": "y"})
    assert msg is not None and "outranks" in msg
