"""
app/scanner/runner.py

Scan orchestrator.

This module:
  1. Validates the target URL (private-network enforcement)
  2. Creates a scan record in the database
  3. Runs all scanner modules sequentially, with rate limiting
  4. Persists each finding and records it in the hash-chained ledger
  5. Updates the scan status when complete

Runs in a background thread so the FastAPI endpoint can return immediately.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlparse

import requests

from app.database import get_conn
from app.evidence import ledger
from app.scanner import (
    banners,
    cookies,
    cors,
    csrf,
    headers,
    paths,
    sqli,
    tls,
    xss,
)
from app.scanner.base import Finding

# Rate limit: seconds between requests within a module pass
REQUEST_INTERVAL = 0.2  # ~5 req/s

# Private / loopback address ranges that are always permitted without user confirmation
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(hostname: str) -> bool:
    """Return True if hostname resolves to a loopback or RFC-1918 address."""
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        pass
    # Try DNS resolution
    import socket
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            addr_str = info[4][0]
            try:
                addr = ipaddress.ip_address(addr_str)
                if any(addr in net for net in _PRIVATE_NETWORKS):
                    return True
            except ValueError:
                continue
    except Exception:
        pass
    return False


def validate_target(url: str, authorized: bool) -> None:
    """
    Raise ValueError if the target is not permitted.
    External (non-private) targets are allowed only when authorized=True.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("Could not determine hostname from the target URL.")

    if not _is_private(hostname) and not authorized:
        raise ValueError(
            "This target appears to be a public/external address. "
            "To scan it, tick the 'I am authorized to test this target' checkbox."
        )


def _make_session() -> requests.Session:
    """Build a requests.Session with sensible defaults and rate-limiting headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SentinelScan/1.0 (security-research; authorized-scan)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    return session


def _persist_finding(finding: Finding, scan_id: int) -> int:
    """Insert a finding into the database and append a ledger entry."""
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO findings
            (scan_id, finding_id, title, category, severity, affected_url,
             description, evidence_raw, evidence_hash, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            finding.finding_id,
            finding.title,
            finding.category,
            finding.severity,
            finding.affected_url,
            finding.description,
            finding.evidence_raw,
            finding.evidence_hash,
            finding.remediation,
        ),
    )
    conn.commit()
    row_id = cur.lastrowid

    ledger.append(
        action="finding_recorded",
        evidence_payload=finding.evidence_raw,
        scan_id=scan_id,
    )
    return row_id


MODULES = [
    ("Security Headers",    headers.run),
    ("Cookie Flags",        cookies.run),
    ("TLS / Certificate",   tls.run),
    ("Server Banners",      banners.run),
    ("Exposed Paths",       paths.run),
    ("CORS Misconfiguration", cors.run),
    ("CSRF Token Check",    csrf.run),
    ("Reflected XSS Probe", xss.run),
    ("SQL Injection Probe", sqli.run),
]


def run_scan(
    scan_id: int,
    target_url: str,
    authorized: bool,
    progress_callback: Callable[[str, str, list[dict]], None] | None = None,
) -> None:
    """
    Execute all scanner modules for the given scan.

    Parameters
    ----------
    scan_id:
        Database row id of the scan.
    target_url:
        The URL to scan.
    authorized:
        Whether the user confirmed authorization for an external target.
    progress_callback:
        Optional callable invoked after each module completes.
        Receives (module_name, status, list_of_finding_dicts).
    """
    conn = get_conn()
    session = _make_session()
    scan_start_perf = time.perf_counter()
    module_timings: dict[str, float] = {}

    try:
        for module_name, module_fn in MODULES:
            mod_start = time.perf_counter()
            try:
                findings: list[Finding] = module_fn(target_url, session)
            except Exception as exc:
                # A module failure must not abort the whole scan
                findings = []
                ledger.append(
                    action="module_error",
                    evidence_payload=f"Module '{module_name}' raised: {exc}",
                    scan_id=scan_id,
                )

            mod_elapsed = round(time.perf_counter() - mod_start, 3)
            module_timings[module_name] = mod_elapsed

            persisted_findings = []
            for f in findings:
                _persist_finding(f, scan_id)
                persisted_findings.append(f.to_dict())

            if progress_callback:
                progress_callback(module_name, "done", persisted_findings)

            # Rate limiting between modules
            time.sleep(REQUEST_INTERVAL)

        # Mark scan complete
        total_duration = round(time.perf_counter() - scan_start_perf, 3)
        finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        
        meta = {
            "total_duration_seconds": total_duration,
            "module_durations": module_timings,
        }
        meta_json = json.dumps(meta)

        conn.execute(
            "UPDATE scans SET status='done', finished_at=?, scan_meta=? WHERE id=?",
            (finished_at, meta_json, scan_id),
        )
        conn.commit()
        ledger.append(
            action="scan_completed",
            evidence_payload=json.dumps({"scan_id": scan_id, "finished_at": finished_at, "meta": meta}),
            scan_id=scan_id,
        )

    except Exception as exc:
        total_duration = round(time.perf_counter() - scan_start_perf, 3)
        meta = {
            "total_duration_seconds": total_duration,
            "module_durations": module_timings,
            "error": str(exc),
        }
        meta_json = json.dumps(meta)
        # Fatal error — mark scan as errored
        conn.execute(
            "UPDATE scans SET status='error', finished_at=?, scan_meta=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), meta_json, scan_id),
        )
        conn.commit()
        ledger.append(
            action="scan_error",
            evidence_payload=f"Fatal error in scan {scan_id}: {exc}",
            scan_id=scan_id,
        )


def start_scan_background(
    scan_id: int,
    target_url: str,
    authorized: bool,
) -> None:
    """Launch run_scan in a daemon thread."""
    t = threading.Thread(
        target=run_scan,
        args=(scan_id, target_url, authorized),
        daemon=True,
    )
    t.start()
