"""
app/main.py

FastAPI application entry point.

Routes:
  GET  /                          → serves the SPA shell (index.html)
  POST /api/scans                 → start a new scan
  GET  /api/scans                 → list all past scans
  GET  /api/scans/{id}            → get scan metadata
  GET  /api/scans/{id}/findings   → get all findings for a scan
  GET  /api/scans/{id}/progress   → SSE stream of live progress
  GET  /api/scans/{id}/integrity  → verify the ledger chain for a scan
  GET  /api/scans/{id}/export/json → download JSON report
  GET  /api/scans/{id}/export/html → download HTML report
  GET  /api/findings/{id}         → get one finding with full evidence
  GET  /api/ledger                → list all ledger entries (paginated)
  GET  /api/integrity             → verify the full ledger chain
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from app.database import init_db, get_conn
from app.evidence import ledger
from app.models import FindingOut, IntegrityResult, LedgerEntryOut, ScanOut, ScanRequest
from app.report import export as report_export
from app.scanner import runner

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Sentinel Scan API", version="1.0.0")

# Serve static files (CSS, JS)
_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# In-memory SSE queues: scan_id → list[asyncio.Queue]
_sse_queues: dict[int, list[asyncio.Queue]] = {}


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ---------------------------------------------------------------------------
# SPA shell
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_index():
    index_path = _STATIC_DIR / "index.html"
    return HTMLResponse(content=index_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------

@app.post("/api/scans", response_model=ScanOut, status_code=201)
def create_scan(body: ScanRequest):
    """Validate the target, create a scan record, and launch the scan thread."""
    # Validate URL and authorization
    try:
        runner.validate_target(body.target_url, body.authorized)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    conn = get_conn()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    cur = conn.execute(
        "INSERT INTO scans (target_url, started_at, status, authorized) VALUES (?, ?, ?, ?)",
        (body.target_url, started_at, "running", int(body.authorized)),
    )
    conn.commit()
    scan_id = cur.lastrowid

    # Log to ledger
    ledger.append(
        action="scan_started",
        evidence_payload=json.dumps({
            "scan_id": scan_id,
            "target_url": body.target_url,
            "authorized": body.authorized,
            "started_at": started_at,
        }),
        scan_id=scan_id,
    )

    if body.authorized:
        ledger.append(
            action="auth_confirmed",
            evidence_payload=f"User confirmed authorization to test {body.target_url}",
            scan_id=scan_id,
        )

    # Progress callback: push SSE events
    def push_progress(module_name: str, status: str, findings: list[dict]) -> None:
        event = json.dumps({
            "module": module_name,
            "status": status,
            "findings": findings,
        })
        # Push to any active SSE subscribers
        for q in _sse_queues.get(scan_id, []):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    # Start the scan in a background thread with progress callback
    import threading
    t = threading.Thread(
        target=runner.run_scan,
        args=(scan_id, body.target_url, body.authorized, push_progress),
        daemon=True,
    )
    t.start()

    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return _scan_row_to_model(row)


@app.get("/api/scans", response_model=list[ScanOut])
def list_scans():
    """Return all scans, most recent first."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC"
    ).fetchall()
    return [_scan_row_to_model(r) for r in rows]


@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_row_to_model(row)


@app.get("/api/scans/{scan_id}/findings", response_model=list[FindingOut])
def get_findings(scan_id: int):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY "
        "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
        "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END ASC, id ASC",
        (scan_id,),
    ).fetchall()
    return [_finding_row_to_model(r) for r in rows]


@app.get("/api/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_row_to_model(row)


# ---------------------------------------------------------------------------
# SSE progress stream
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/progress")
async def scan_progress(scan_id: int):
    """
    Server-Sent Events stream for live scan progress.
    Each event is a JSON object: {module, status, findings}.
    The stream ends when the scan status leaves 'running'.
    """
    conn = get_conn()
    scan_row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan_row:
        raise HTTPException(status_code=404, detail="Scan not found")

    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _sse_queues.setdefault(scan_id, []).append(q)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                # Check if scan is still running
                scan_check = conn.execute(
                    "SELECT status FROM scans WHERE id=?", (scan_id,)
                ).fetchone()
                scan_status = scan_check["status"] if scan_check else "done"

                # Drain the queue
                try:
                    while True:
                        event_data = q.get_nowait()
                        yield f"data: {event_data}\n\n"
                except asyncio.QueueEmpty:
                    pass

                if scan_status != "running":
                    # Send final status event
                    yield f"data: {json.dumps({'type': 'done', 'status': scan_status})}\n\n"
                    break

                await asyncio.sleep(0.3)
        finally:
            queues = _sse_queues.get(scan_id, [])
            if q in queues:
                queues.remove(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Integrity check
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/integrity", response_model=IntegrityResult)
def check_scan_integrity(scan_id: int):
    result = ledger.verify_chain(scan_id=scan_id)
    ledger.append(
        action="integrity_check",
        evidence_payload=json.dumps(result),
        scan_id=scan_id,
    )
    return IntegrityResult(**result)


@app.get("/api/integrity", response_model=IntegrityResult)
def check_full_integrity():
    result = ledger.verify_chain(scan_id=None)
    ledger.append(
        action="integrity_check_full",
        evidence_payload=json.dumps(result),
    )
    return IntegrityResult(**result)


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/export/json")
def export_json_report(scan_id: int):
    data = report_export.export_json(scan_id)
    if "error" in data:
        raise HTTPException(status_code=404, detail=data["error"])
    return JSONResponse(
        content=data,
        headers={
            "Content-Disposition": f'attachment; filename="sentinel-scan-{scan_id}.json"'
        },
    )


@app.get("/api/scans/{scan_id}/export/html", response_class=HTMLResponse)
def export_html_report(scan_id: int):
    html = report_export.export_html(scan_id)
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="sentinel-scan-{scan_id}.html"'
        },
    )


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

@app.get("/api/ledger", response_model=list[LedgerEntryOut])
def get_ledger(scan_id: int | None = None, limit: int = 200, offset: int = 0):
    conn = get_conn()
    if scan_id is not None:
        rows = conn.execute(
            "SELECT * FROM ledger WHERE scan_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
            (scan_id, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM ledger ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [_ledger_row_to_model(r) for r in rows]


# ---------------------------------------------------------------------------
# Helper converters
# ---------------------------------------------------------------------------

def _scan_row_to_model(row) -> ScanOut:
    return ScanOut(
        id=row["id"],
        target_url=row["target_url"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        status=row["status"],
        authorized=bool(row["authorized"]),
        scan_meta=row["scan_meta"],
    )


def _finding_row_to_model(row) -> FindingOut:
    return FindingOut(
        id=row["id"],
        scan_id=row["scan_id"],
        finding_id=row["finding_id"],
        title=row["title"],
        category=row["category"],
        severity=row["severity"],
        affected_url=row["affected_url"],
        description=row["description"],
        evidence_raw=row["evidence_raw"],
        evidence_hash=row["evidence_hash"],
        remediation=row["remediation"],
    )


def _ledger_row_to_model(row) -> LedgerEntryOut:
    return LedgerEntryOut(
        id=row["id"],
        timestamp=row["timestamp"],
        scan_id=row["scan_id"],
        action=row["action"],
        evidence_hash=row["evidence_hash"],
        prev_hash=row["prev_hash"],
        entry_hash=row["entry_hash"],
    )
