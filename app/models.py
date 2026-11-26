"""
app/models.py

Pydantic request/response models used by the FastAPI routes.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, HttpUrl, field_validator


class ScanRequest(BaseModel):
    target_url: str
    authorized: bool = False  # True when user has ticked the authorization checkbox

    @field_validator("target_url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class FindingOut(BaseModel):
    id: int
    scan_id: int
    finding_id: str
    title: str
    category: str
    severity: str
    affected_url: str
    description: str
    evidence_raw: str
    evidence_hash: str
    remediation: str


class ScanOut(BaseModel):
    id: int
    target_url: str
    started_at: str
    finished_at: Optional[str]
    status: str
    authorized: bool
    scan_meta: Optional[str]


class LedgerEntryOut(BaseModel):
    id: int
    timestamp: str
    scan_id: Optional[int]
    action: str
    evidence_hash: str
    prev_hash: str
    entry_hash: str


class IntegrityResult(BaseModel):
    ok: bool
    checked: int
    first_broken_id: Optional[int]
    message: str
