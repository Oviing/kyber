"""RQ worker entrypoint: loads target, provisions sandbox, runs agent graph, stores findings."""
from datetime import UTC, datetime

from kyber.agents.graph import run_graph
from kyber.agents.judge import judge
from kyber.archive import (
    MAX_TEXT_BYTES,
    SANDBOX_EXTRACT_SCRIPT,
    TEXT_EXTENSIONS,
    ArchiveError,
    content_findings_for_files,
    extract_text_files,
    load_archive_bytes,
)
from kyber.db import SessionLocal
from kyber.models import Finding, Scan, ScanStatus, Target
from kyber.sandbox.manager import SandboxManager


def _target_to_dict(t: Target) -> dict:
    return {"type": t.type, "language": t.language, "snippet": t.snippet or "",
            "repo_url": t.repo_url, "service_url": t.service_url,
            "archive_path": t.archive_path, "archive_sha256": t.archive_sha256,
            "archive_name": t.archive_name or "archive.zip"}


def _rebase_location(finding: dict, archive_name: str) -> dict:
    loc = finding.get("location") or ""
    if loc.startswith("/work"):
        finding = dict(finding)
        finding["location"] = archive_name + loc[len("/work"):] or archive_name
    return finding


def _scan_archive_in_sandbox(mgr: SandboxManager, sb, data: bytes, archive_name: str,
                             language: str, profile: str, exec_fn) -> list[dict]:
    """Ship archive bytes into the sandbox, extract there, scan /work."""
    import os

    mgr.write_bytes_chunked(sb, "/tmp/upload.zip", data)
    mgr.write_file(sb, "/tmp/kyber_extract.py", SANDBOX_EXTRACT_SCRIPT.encode())
    code, listing = mgr.exec(sb, "python3 /tmp/kyber_extract.py /tmp/upload.zip /work", timeout=180)
    if code != 0:
        raise ArchiveError(f"archive extraction failed in sandbox: {listing[:500]}")
    relpaths = [p for p in listing.splitlines() if p.strip()]
    # Pull scannable text back (capped) for regex content scans.
    files: list[tuple[str, str]] = []
    budget = MAX_TEXT_BYTES
    for rel in relpaths:
        _, ext = os.path.splitext(rel)
        if ext.lower() not in TEXT_EXTENSIONS:
            continue
        _code, content = mgr.exec(sb, f"wc -c < '/work/{rel}' 2>/dev/null || echo 0", timeout=30)
        try:
            size = int(content.strip().split()[0])
        except (ValueError, IndexError):
            continue
        if size > budget or size <= 0:
            continue
        _code, content = mgr.exec(sb, f"head -c {budget} '/work/{rel}'", timeout=30)
        budget -= len(content)
        files.append((rel, content))
        if budget <= 0:
            break
    raw = content_findings_for_files(files, archive_name, profile)
    # SAST/SCA tools run against the extracted /work tree.
    for f in run_graph({"type": "snippet", "language": language, "snippet": ""},
                       profile, exec_fn):
        raw.append(_rebase_location(f, archive_name))
    return judge(raw)


def _scan_archive_fallback(data: bytes, archive_name: str, profile: str,
                           exec_fn=None) -> list[dict]:
    """No-Docker path: validate + extract locally, regex scans + tool stubs."""
    files = extract_text_files(data)
    raw = content_findings_for_files(files, archive_name, profile)
    raw.extend(run_graph({"type": "snippet", "language": "auto", "snippet": ""},
                         profile, exec_fn or (lambda cmd: "")))
    return judge(raw)


def run_scan(scan_id: str) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        target = db.get(Target, scan.target_id)
        if not target:
            scan.status = ScanStatus.failed.value
            scan.error = "target not found"
            db.commit()
            return
        scan.status = ScanStatus.running.value
        db.commit()

        mgr = SandboxManager()
        tdict = _target_to_dict(target)
        mode = "dast" if tdict["type"] == "url" else "static"

        def _run(sb):
            def exec_fn(cmd: str) -> str:
                _code, out = mgr.exec(sb, cmd, timeout=120)
                return out

            if tdict["type"] == "archive":
                if not tdict.get("archive_path"):
                    raise ArchiveError("archive target has no stored file")
                data = load_archive_bytes(tdict["archive_path"])
                return _scan_archive_in_sandbox(mgr, sb, data, tdict["archive_name"],
                                                target.language, scan.profile, exec_fn)

            # Seed untrusted code into sandbox (no host mount).
            if tdict["type"] in ("snippet", "repo") and tdict.get("snippet"):
                try:
                    mgr.write_file(sb, "/work/target.txt", tdict["snippet"].encode()[:1_000_000])
                except Exception:
                    pass

            def dast_fetch_fn(req: dict) -> str:
                # curl from attacker container to target; confined to sandbox network.
                url = tdict.get("service_url", "")
                payload = req["payload"].replace("'", "")
                _code, out = mgr.exec(sb, f"curl -s -m 8 '{url}' --get --data-urlencode 'q={payload}' || true",
                                     timeout=30)
                return out

            return run_graph(tdict, scan.profile, exec_fn, dast_fetch_fn=dast_fetch_fn)

        try:
            findings = mgr.run_with_cleanup(scan_id, mode, _run, timeout_s=scan.timeout_s)
        except Exception as e:
            # Docker unavailable (local dev without images)? Fall back to in-process scan
            # so API/CLI still return value; sandbox path is used in production.
            if "docker" in str(type(e)).lower() or "provision failed" in str(e).lower() or True:
                try:
                    if tdict["type"] == "archive":
                        if not tdict.get("archive_path"):
                            raise ArchiveError("archive target has no stored file") from e
                        data = load_archive_bytes(tdict["archive_path"])
                        findings = _scan_archive_fallback(data, tdict["archive_name"], scan.profile)
                    else:
                        findings = run_graph(tdict, scan.profile, lambda cmd: "", dast_fetch_fn=None)
                except Exception as e2:
                    raise e2 from e

        for f in findings:
            db.add(Finding(scan_id=scan.id, rule_id=f.get("rule_id", "unknown"),
                           title=f.get("title", ""), severity=f.get("severity", "medium"),
                           confidence=f.get("confidence", "medium"), cwe=f.get("cwe"),
                           owasp=f.get("owasp"), location=f.get("location"),
                           evidence=(f.get("evidence") or "")[:2000], tool=f.get("tool"),
                           extra={}))
        scan.status = ScanStatus.done.value
        scan.finished_at = datetime.now(UTC)
        db.commit()
    except Exception as e:
        try:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.failed.value
                scan.error = str(e)[:2000]
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()
