"""
app/scanner/base.py

Shared Finding dataclass used by every scanner module.
All modules return a list[Finding].  The runner persists them and feeds them
into the ledger.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Optional


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass
class Finding:
    title: str
    category: str           # OWASP Top 10 label, e.g. "A05 Security Misconfiguration"
    severity: str           # Critical / High / Medium / Low / Info
    affected_url: str
    description: str
    evidence_raw: str       # Full HTTP request + response excerpt, plain text
    remediation: str
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def evidence_hash(self) -> str:
        """SHA-256 of the raw evidence string, computed on demand."""
        return hashlib.sha256(self.evidence_raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "affected_url": self.affected_url,
            "description": self.description,
            "evidence_raw": self.evidence_raw,
            "evidence_hash": self.evidence_hash,
            "remediation": self.remediation,
        }


def build_evidence(
    method: str,
    url: str,
    request_headers: dict,
    request_body: Optional[str],
    status_code: int,
    response_headers: dict,
    response_excerpt: str,
    notes: str = "",
) -> str:
    """
    Assemble a human-readable evidence block from request/response components.
    This is what gets stored verbatim and hashed.
    """
    req_header_lines = "\n".join(f"{k}: {v}" for k, v in request_headers.items())
    resp_header_lines = "\n".join(f"{k}: {v}" for k, v in response_headers.items())

    body_section = ""
    if request_body:
        body_section = f"\nRequest Body:\n{request_body[:2000]}\n"

    excerpt = response_excerpt[:3000] if response_excerpt else "(no body)"

    parts = [
        "=== REQUEST ===",
        f"{method} {url}",
        req_header_lines or "(no headers recorded)",
        body_section,
        "",
        "=== RESPONSE ===",
        f"Status: {status_code}",
        resp_header_lines or "(no response headers)",
        "",
        "Response excerpt:",
        excerpt,
    ]
    if notes:
        parts += ["", "=== NOTES ===", notes]

    return "\n".join(parts)
