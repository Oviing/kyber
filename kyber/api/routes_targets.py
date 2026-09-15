from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from kyber.api.auth import require_api_key
from kyber.archive import MAX_UPLOAD_BYTES, ArchiveError, find_archive_by_sha256, store_archive
from kyber.db import get_db
from kyber.models import Target, TargetCreate

router = APIRouter(prefix="/v1/targets", tags=["targets"])


@router.post("")
def create_target(body: TargetCreate, db: Session = Depends(get_db), _=Depends(require_api_key)):
    if body.type.value == "snippet" and not body.snippet:
        raise HTTPException(400, "snippet required for type=snippet")
    if body.type.value == "repo" and not body.repo_url:
        raise HTTPException(400, "repo_url required for type=repo")
    if body.type.value == "url" and not body.service_url:
        raise HTTPException(400, "service_url required for type=url")
    archive_path: str | None = None
    if body.type.value == "archive":
        if not body.archive_sha256:
            raise HTTPException(400, "archive_sha256 required for type=archive (upload first)")
        archive_path = find_archive_by_sha256(body.archive_sha256)
        if archive_path is None:
            raise HTTPException(404, "archive not found for sha256")
    t = Target(type=body.type.value, language=body.language, snippet=body.snippet,
               repo_url=body.repo_url, repo_ref=body.repo_ref, service_url=body.service_url,
               archive_path=archive_path, archive_sha256=body.archive_sha256,
               archive_name=body.archive_name)
    db.add(t)
    db.commit()
    db.refresh(t)
    return {"id": t.id, "type": t.type}


@router.post("/upload")
def upload_target(file: UploadFile = File(...), language: str = Form("auto"),
                  db: Session = Depends(get_db), _=Depends(require_api_key)):
    data = file.file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file too large ({len(data)} bytes, max {MAX_UPLOAD_BYTES})")
    try:
        path, sha = store_archive(data, file.filename or "")
    except ArchiveError as e:
        raise HTTPException(400, str(e)) from e
    t = Target(type="archive", language=language, archive_path=path,
               archive_sha256=sha, archive_name=file.filename)
    db.add(t)
    db.commit()
    db.refresh(t)
    return {"id": t.id, "type": t.type, "sha256": sha, "filename": file.filename}
