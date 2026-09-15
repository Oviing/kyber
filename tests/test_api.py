from fastapi.testclient import TestClient

from kyber.api.main import app
from kyber.db import init_db

init_db()
c = TestClient(app)
H = {"X-API-Key": "dev-key-1"}


def test_health():
    assert c.get("/health").json()["ok"] is True


def test_target_scan_flow_inline():
    t = c.post("/v1/targets", json={"type": "snippet", "language": "python",
                                    "snippet": "import subprocess; subprocess.call('ls')"}, headers=H).json()
    assert "id" in t
    s = c.post("/v1/scans", json={"target_id": t["id"], "profile": "quick"}, headers=H).json()
    assert "id" in s
    got = c.get(f"/v1/scans/{s['id']}", headers=H).json()
    assert got["status"] in ("done", "queued", "running", "failed")
    f = c.get(f"/v1/scans/{s['id']}/findings", headers=H).json()
    assert isinstance(f, list)
    sarif = c.get(f"/v1/scans/{s['id']}/report.sarif", headers=H).json()
    assert sarif["version"] == "2.1.0"


def test_url_requires_consent():
    t = c.post("/v1/targets", json={"type": "url", "service_url": "http://example.com"}, headers=H).json()
    r = c.post("/v1/scans", json={"target_id": t["id"], "profile": "full"}, headers=H)
    assert r.status_code == 400
