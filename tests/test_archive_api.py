import io
import zipfile

from fastapi.testclient import TestClient

from kyber.api.main import app
from kyber.db import init_db

init_db()
c = TestClient(app)
H = {"X-API-Key": "dev-key-1"}


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


SECRET_ZIP = make_zip({"calc.py": b"api_key = 'sk-1234567890abcdef'\nprint('hi')\n"})


def test_upload_zip_ok():
    r = c.post("/v1/targets/upload", files={"file": ("calc.zip", SECRET_ZIP, "application/zip")},
               data={"language": "python"}, headers=H)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "archive"
    assert body["sha256"]


def test_upload_non_zip_rejected():
    r = c.post("/v1/targets/upload", files={"file": ("x.bin", b"\x8d\x07nope", "application/octet-stream")},
               headers=H)
    assert r.status_code == 400


def test_upload_zip_slip_rejected():
    bad = make_zip({"../../evil.sh": b"evil"})
    r = c.post("/v1/targets/upload", files={"file": ("evil.zip", bad, "application/zip")}, headers=H)
    assert r.status_code == 400


def test_archive_scan_flow_finds_secret():
    t = c.post("/v1/targets/upload", files={"file": ("calc.zip", SECRET_ZIP, "application/zip")},
               data={"language": "python"}, headers=H).json()
    s = c.post("/v1/scans", json={"target_id": t["id"], "profile": "quick"}, headers=H).json()
    got = c.get(f"/v1/scans/{s['id']}", headers=H).json()
    assert got["status"] == "done", got
    findings = c.get(f"/v1/scans/{s['id']}/findings", headers=H).json()
    secrets = [f for f in findings if f["rule_id"].startswith("secret/")]
    assert secrets, findings
    assert all(f["location"].startswith("calc.zip:") for f in secrets)


def test_json_archive_requires_sha():
    r = c.post("/v1/targets", json={"type": "archive", "language": "python"}, headers=H)
    assert r.status_code == 400
