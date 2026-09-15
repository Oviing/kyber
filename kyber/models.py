"""SQLAlchemy models + Pydantic schemas for targets/scans/findings."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import JSON, DateTime, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TargetType(str, Enum):
    snippet = "snippet"
    repo = "repo"
    url = "url"
    archive = "archive"


class ScanProfile(str, Enum):
    quick = "quick"
    full = "full"
    adversarial = "adversarial"


class ScanStatus(str, Enum):
    queued = "queued"
    provisioning = "provisioning"
    running = "running"
    scoring = "scoring"
    done = "done"
    failed = "failed"
    timeout = "timeout"


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type: Mapped[str] = mapped_column(String(16))
    language: Mapped[str] = mapped_column(String(32), default="auto")
    snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    repo_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    repo_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    service_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    archive_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    archive_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    archive_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String(36))
    profile: Mapped[str] = mapped_column(String(16), default="quick")
    status: Mapped[str] = mapped_column(String(16), default="queued")
    consent_owned: Mapped[bool] = mapped_column(default=False)
    timeout_s: Mapped[int] = mapped_column(default=300)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36))
    rule_id: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))  # critical/high/medium/low/info
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    cwe: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    owasp: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)


# ---- API schemas ----
class TargetCreate(BaseModel):
    type: TargetType
    language: str = "auto"
    snippet: Optional[str] = Field(default=None, max_length=1_000_000)
    repo_url: Optional[str] = None
    repo_ref: Optional[str] = "HEAD"
    service_url: Optional[str] = None
    archive_sha256: Optional[str] = None
    archive_name: Optional[str] = None


class ScanCreate(BaseModel):
    target_id: str
    profile: ScanProfile = ScanProfile.quick
    consent_owned: bool = False
    timeout_s: Optional[int] = None


class FindingOut(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    location: Optional[str] = None
    evidence: Optional[str] = None
    tool: Optional[str] = None
