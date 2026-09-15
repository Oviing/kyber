from typer.testing import CliRunner

from kyber.cli import app, looks_like_zip, read_text_file

runner = CliRunner()


def test_bare_kyber_runs_wizard_without_traceback(monkeypatch):
    import kyber.cli as cli_mod

    monkeypatch.setattr(cli_mod, "ensure_api_up", lambda api: "reused")
    result = runner.invoke(app, [], input="\n\n")
    assert result.exit_code == 0
    assert "Traceback" not in result.output


def test_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "submit" in result.output
    for cmd in ("wizard", "up", "down", "doctor"):
        assert cmd in result.output


def test_read_text_file_ok(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("print('hi')", encoding="utf-8")
    assert read_text_file(str(p)) == "print('hi')"


def test_read_text_file_binary_gives_clean_error(tmp_path):
    import typer

    p = tmp_path / "x.bin"
    p.write_bytes(b"\x8d\x07\xff\xfe not utf-8")
    try:
        read_text_file(str(p))
    except typer.BadParameter as e:
        assert ".zip" in str(e)
    else:
        raise AssertionError("expected BadParameter")


def test_looks_like_zip(tmp_path):
    z = tmp_path / "a.zip"
    z.write_bytes(b"PK\x03\x04fake")
    assert looks_like_zip(str(z)) is True
    t = tmp_path / "a.py"
    t.write_text("x = 1", encoding="utf-8")
    assert looks_like_zip(str(t)) is False
    b = tmp_path / "noext"
    b.write_bytes(b"PK\x03\x04fake")
    assert looks_like_zip(str(b)) is True
