"""Archive (.zip) target support.

Security model: untrusted archives are NEVER extracted on the API host in
production. The worker ships raw bytes into the sandbox and extracts them
inside the container with the same guards defined here. The pure-python
helpers below are shared by both paths (sandbox extractor script embeds the
same checks) and by the no-Docker local fallback.
"""
import hashlib
import io
import os
import stat
import zipfile

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_BYTES = 200 * 1024 * 1024
MAX_FILES = 5000
MAX_RATIO = 100  # max total uncompressed size / compressed size (zip-bomb guard)
MAX_TEXT_BYTES = 1_000_000  # cap on text pulled back for regex scans

# Extensions treated as scannable text. Everything else is skipped for
# content scans but still listed / passed to SAST tools in-sandbox.
TEXT_EXTENSIONS = frozenset(
    {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
        ".c", ".h", ".cpp", ".hpp", ".cs", ".swift", ".kt", ".rs", ".sh",
        ".yml", ".yaml", ".json", ".xml", ".html", ".txt", ".md", ".cfg",
        ".ini", ".toml", ".env",
    }
)


class ArchiveError(ValueError):
    pass


def is_zip_bytes(data: bytes) -> bool:
    return len(data) >= 4 and data[:2] == b"PK"


def validate_zip_bytes(data: bytes, filename: str = "") -> None:
    if filename and not filename.lower().endswith(".zip"):
        raise ArchiveError(f"only .zip archives are supported (got {filename!r})")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ArchiveError(f"archive too large ({len(data)} bytes, max {MAX_UPLOAD_BYTES})")
    if not is_zip_bytes(data):
        raise ArchiveError("not a zip archive (bad magic bytes)")


def _check_member_name(name: str) -> None:
    if not name or name.startswith(("/", "\\")):
        raise ArchiveError(f"archive member with absolute path: {name!r}")
    parts = name.replace("\\", "/").split("/")
    if any(p == ".." for p in parts):
        raise ArchiveError(f"archive member escapes directory (zip-slip): {name!r}")


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK


def safe_member_list(data: bytes) -> list[zipfile.ZipInfo]:
    """Validate an archive and return its file members (dirs skipped).

    Raises ArchiveError on zip-slip paths, symlinks, file-count, size, or
    compression-ratio violations.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise ArchiveError(f"corrupt zip archive: {e}") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ArchiveError(f"too many archive members ({len(infos)}, max {MAX_FILES})")
        total = 0
        files: list[zipfile.ZipInfo] = []
        for info in infos:
            if info.is_dir():
                continue
            _check_member_name(info.filename)
            if _is_symlink(info):
                raise ArchiveError(f"archive member is a symlink: {info.filename!r}")
            total += info.file_size
            files.append(info)
        if total > MAX_EXTRACTED_BYTES:
            raise ArchiveError(f"archive extracts to {total} bytes (max {MAX_EXTRACTED_BYTES})")
        if data and total // max(len(data), 1) > MAX_RATIO:
            raise ArchiveError(f"archive compression ratio too high ({total}/{len(data)})")
        return files


def _archive_dir() -> str:
    from kyber.config import settings

    d = os.path.join(settings.artifact_dir, "archives")
    os.makedirs(d, exist_ok=True)
    return d


def store_archive(data: bytes, filename: str) -> tuple[str, str]:
    """Validate + store an archive content-addressed. Returns (path, sha256)."""
    validate_zip_bytes(data, filename)
    safe_member_list(data)  # reject slips/bombs/symlinks at upload time too
    sha = hashlib.sha256(data).hexdigest()
    path = os.path.join(_archive_dir(), f"{sha}.zip")
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(data)
    return path, sha


def find_archive_by_sha256(sha: str) -> str | None:
    path = os.path.join(_archive_dir(), f"{sha}.zip")
    return path if os.path.exists(path) else None


def load_archive_bytes(archive_path: str) -> bytes:
    with open(archive_path, "rb") as fh:
        return fh.read()


def extract_text_files(data: bytes, max_bytes: int = MAX_TEXT_BYTES) -> list[tuple[str, str]]:
    """Extract scannable text files from an archive (fallback / content-scan path).

    Returns [(relative_path, text)]. Binary or oversized members are skipped.
    """
    members = safe_member_list(data)
    zf = zipfile.ZipFile(io.BytesIO(data))
    out: list[tuple[str, str]] = []
    budget = max_bytes
    with zf:
        for info in members:
            _, ext = os.path.splitext(info.filename)
            if ext.lower() not in TEXT_EXTENSIONS:
                continue
            if info.file_size > max_bytes:
                continue
            raw = zf.read(info.filename)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if len(text) > budget:
                break
            budget -= len(text)
            out.append((info.filename, text))
    return out


# Python script executed INSIDE the sandbox container to extract the archive
# with the same guards. Reads argv: src_zip, dest_dir. Prints relpaths, one
# per line, of extracted files.
SANDBOX_EXTRACT_SCRIPT = r"""
import os, stat, sys, zipfile
MAX_FILES = %d
MAX_EXTRACTED = %d
MAX_RATIO = %d
src, dest = sys.argv[1], sys.argv[2]
with open(src, 'rb') as fh:
    data = fh.read()
zf = zipfile.ZipFile(__import__('io').BytesIO(data))
infos = zf.infolist()
if len(infos) > MAX_FILES:
    sys.exit('too many members')
total = sum(i.file_size for i in infos if not i.is_dir())
if total > MAX_EXTRACTED:
    sys.exit('extracted too large')
if data and total // max(len(data), 1) > MAX_RATIO:
    sys.exit('compression ratio too high')
out = []
for i in infos:
    if i.is_dir():
        continue
    name = i.filename
    parts = name.replace('\\', '/').split('/')
    if not name or name.startswith("/") or any(p == ".." for p in parts):
        sys.exit('zip-slip: ' + name)
    if ((i.external_attr >> 16) & 0o170000) == 0o120000:
        sys.exit('symlink: ' + name)
    target = os.path.join(dest, *parts)
    os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
    with open(target, 'wb') as fh:
        fh.write(zf.read(name))
    out.append(name)
print('\n'.join(out))
""" % (MAX_FILES, MAX_EXTRACTED_BYTES, MAX_RATIO)  # noqa: UP031 - % avoids {} conflicts


def content_findings_for_files(files: list[tuple[str, str]], archive_name: str,
                               profile: str = "quick") -> list[dict]:
    """Regex-based findings over extracted text files (shared sandbox/fallback path)."""
    from kyber.tools.adversarial import scan_ai_code
    from kyber.tools.safe_probes import static_secret_scan

    raw: list[dict] = []
    for relpath, text in files:
        loc = f"{archive_name}:{relpath}"
        for f in static_secret_scan(text, loc):
            raw.append({**f, "location": loc})
        if profile == "adversarial":
            for f in scan_ai_code(text):
                raw.append({**f, "location": loc})
    return raw
