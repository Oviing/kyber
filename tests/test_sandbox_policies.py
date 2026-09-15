import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from kyber.sandbox import policies


def test_forbidden_payloads_blocked():
    assert not policies.is_payload_allowed("rm -rf / tmp")
    assert not policies.is_payload_allowed("echo :(){:|:&};: hi")
    assert policies.is_payload_allowed("semgrep --config auto /work")


def test_container_kwargs_hardened():
    kw = policies.container_kwargs("img", "n", "net", policies.DEFAULT_LIMITS)
    assert kw["read_only"] is True
    assert kw["cap_drop"] == ["ALL"]
    assert kw["user"] == "65532"
    assert "no-new-privileges" in kw["security_opt"]
