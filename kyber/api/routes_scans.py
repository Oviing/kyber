from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from kyber.agents.judge import to_sarif
from kyber.api.auth import require_api_key
from kyber.config import settings
from kyber.db import get_db
from kyber.models import Finding, FindingOut, Scan, ScanCreate, ScanStatus, Target
from kyber.queue import enqueue_scan

router = APIRouter(prefix="/v1/scans", tags=["scans"])

PROFILE_TIMEOUTS = {"quick": settings.sandbox_timeout_quick, "full": settings.sandbox_timeout_full,
                    "adversarial": 600, "agent": 900}


@router.post("")
def create_scan(body: ScanCreate, db: Session = Depends(get_db), _=Depends(require_api_key)):
    target = db.get(Target, body.target_id)
    if not target:
        raise HTTPException(404, "target not found")
    if target.type == "url" and not body.consent_owned:
        raise HTTPException(400, "consent_owned=true required for url targets")
    timeout = body.timeout_s or PROFILE_TIMEOUTS.get(body.profile.value, 300)
    timeout = min(timeout, settings.sandbox_timeout_full)
    s = Scan(target_id=target.id, profile=body.profile.value, status=ScanStatus.queued.value,
             consent_owned=body.consent_owned, timeout_s=timeout,
             goal=(body.goal or None))
    db.add(s)
    db.commit()
    db.refresh(s)
    enqueue_scan(s.id)
    # re-read status (inline fallback may have completed already)
    db.refresh(s)
    return {"id": s.id, "status": s.status}


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db), _=Depends(require_api_key)):
    s = db.get(Scan, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    return {"id": s.id, "target_id": s.target_id, "profile": s.profile, "status": s.status,
            "error": s.error, "timeout_s": s.timeout_s,
            "goal": getattr(s, "goal", None)}


@router.get("/{scan_id}/findings")
def list_findings(scan_id: str, db: Session = Depends(get_db), _=Depends(require_api_key)):
    rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return [FindingOut(id=r.id, rule_id=r.rule_id, title=r.title, severity=r.severity,
                       confidence=r.confidence, cwe=r.cwe, owasp=r.owasp, location=r.location,
                       evidence=r.evidence, tool=r.tool).model_dump() for r in rows]


@router.get("/{scan_id}/report.sarif")
def sarif_report(scan_id: str, db: Session = Depends(get_db), _=Depends(require_api_key)):
    s = db.get(Scan, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings = [{"rule_id": r.rule_id, "title": r.title, "severity": r.severity,
                 "location": r.location, "evidence": r.evidence} for r in rows]
    return to_sarif(findings, scan_id)


@router.delete("/{scan_id}")
def cancel_scan(scan_id: str, db: Session = Depends(get_db), _=Depends(require_api_key)):
    s = db.get(Scan, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    if s.status in (ScanStatus.done.value, ScanStatus.failed.value):
        return {"id": s.id, "status": s.status}
    s.status = ScanStatus.failed.value
    s.error = "cancelled by user"
    db.commit()
    return {"id": s.id, "status": s.status}
