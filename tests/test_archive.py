import io
import stat
import zipfile

import pytest

from kyber import archive
from kyber.archive import ArchiveError


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_validate_good_zip():
    data = make_zip({"app.py": b"print('hi')"})
    archive.validate_zip_bytes(data, "app.zip")  # no raise


def test_validate_bad_magic():
    with pytest.raises(ArchiveError):
        archive.validate_zip_bytes(b"\x8d\x07not a zip", "x.zip")


def test_validate_wrong_extension():
    data = make_zip({"a.py": b"x"})
    with pytest.raises(ArchiveError):
        archive.validate_zip_bytes(data, "x.tar.gz")


def test_validate_oversize(monkeypatch):
    monkeypatch.setattr(archive, "MAX_UPLOAD_BYTES", 10)
    with pytest.raises(ArchiveError):
        archive.validate_zip_bytes(make_zip({"a.py": b"x" * 100}), "x.zip")


def test_zip_slip_rejected():
    data = make_zip({"../../evil.sh": b"evil", "ok.py": b"ok"})
    with pytest.raises(ArchiveError, match="zip-slip"):
        archive.safe_member_list(data)
    with pytest.raises(ArchiveError):
        archive.store_archive(data, "evil.zip")


def test_absolute_path_rejected():
    data = make_zip({"/tmp/evil.sh": b"evil"})
    with pytest.raises(ArchiveError):
        archive.safe_member_list(data)


def test_symlink_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "target")
    with pytest.raises(ArchiveError, match="symlink"):
        archive.safe_member_list(buf.getvalue())


def test_ratio_guard(monkeypatch):
    monkeypatch.setattr(archive, "MAX_RATIO", 1)
    data = make_zip({"big.txt": b"A" * 100000})
    with pytest.raises(ArchiveError, match="ratio"):
        archive.safe_member_list(data)


def test_store_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr("kyber.config.settings.artifact_dir", str(tmp_path))
    data = make_zip({"app.py": b"print('hi')"})
    path, sha = archive.store_archive(data, "app.zip")
    assert archive.load_archive_bytes(path) == data
    assert archive.find_archive_by_sha256(sha) == path
    assert archive.find_archive_by_sha256("0" * 64) is None


def test_extract_text_files_skips_binary():
    data = make_zip({"app.py": "api_key = 'sk-1234567890abcdef'",
                     "img.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 100})
    files = dict(archive.extract_text_files(data))
    assert "app.py" in files
    assert "img.png" not in files


def test_content_findings_locations():
    files = [("app.py", "api_key = 'sk-1234567890abcdef'")]
    out = archive.content_findings_for_files(files, "app.zip", "quick")
    assert any(f["rule_id"].startswith("secret/") for f in out)
    assert all(f["location"].startswith("app.zip:") for f in out)
