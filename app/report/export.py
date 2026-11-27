"""
app/report/export.py

Report generation module.

Provides two export formats:
  1. JSON export  — machine-readable, includes all findings and ledger tail hash
  2. HTML export  — self-contained, print-friendly (browser Print > Save as PDF)

Both exports are generated on demand from the database; nothing is cached.
"""

from __future__ import annotations

import json
import html as html_lib
from datetime import datetime, timezone
from typing import Optional

from app.database import get_conn


def _get_scan(scan_id: int) -> Optional[dict]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def _get_findings(scan_id: int) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY "
        "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
        "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END ASC",
        (scan_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _get_ledger_tail_hash(scan_id: int) -> str:
    conn = get_conn()
    row = conn.execute(
        "SELECT entry_hash FROM ledger WHERE scan_id=? ORDER BY id DESC LIMIT 1",
        (scan_id,),
    ).fetchone()
    return row["entry_hash"] if row else "no ledger entries"


def export_json(scan_id: int) -> dict:
    """Return a dict ready to be serialised as JSON."""
    scan = _get_scan(scan_id)
    if not scan:
        return {"error": f"Scan {scan_id} not found"}

    findings = _get_findings(scan_id)
    tail_hash = _get_ledger_tail_hash(scan_id)

    severity_counts: dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    }
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    scan_meta = {}
    if scan.get("scan_meta"):
        try:
            scan_meta = json.loads(scan["scan_meta"])
        except Exception:
            scan_meta = {"raw": scan["scan_meta"]}

    return {
        "report_meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "Sentinel Scan",
            "version": "1.0.0",
        },
        "scan": scan,
        "timing": {
            "total_duration_seconds": scan_meta.get("total_duration_seconds"),
            "module_durations": scan_meta.get("module_durations", {}),
        },
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "total_duration_seconds": scan_meta.get("total_duration_seconds"),
            "ledger_tail_hash": tail_hash,
        },
        "findings": findings,
    }


def _severity_badge(severity: str) -> str:
    classes = {
        "Critical": "badge-critical",
        "High":     "badge-high",
        "Medium":   "badge-medium",
        "Low":      "badge-low",
        "Info":     "badge-info",
    }
    cls = classes.get(severity, "badge-info")
    return f'<span class="badge {cls}">{html_lib.escape(severity)}</span>'


def export_html(scan_id: int) -> str:
    """Return a self-contained HTML string for the report."""
    scan = _get_scan(scan_id)
    if not scan:
        return "<html><body><p>Scan not found.</p></body></html>"

    findings = _get_findings(scan_id)
    tail_hash = _get_ledger_tail_hash(scan_id)

    severity_counts: dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    }
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Build findings HTML
    findings_html = ""
    for idx, f in enumerate(findings, 1):
        findings_html += f"""
        <section class="finding" id="finding-{f['id']}">
          <h3><span class="num">{idx}.</span> {html_lib.escape(f['title'])}
            {_severity_badge(f['severity'])}
          </h3>
          <table class="meta-table">
            <tr><th>Category</th><td>{html_lib.escape(f['category'])}</td></tr>
            <tr><th>Severity</th><td>{_severity_badge(f['severity'])}</td></tr>
            <tr><th>Affected URL</th><td><code>{html_lib.escape(f['affected_url'])}</code></td></tr>
            <tr><th>Evidence SHA-256</th><td><code class="hash">{html_lib.escape(f['evidence_hash'])}</code></td></tr>
          </table>
          <h4>Description</h4>
          <p>{html_lib.escape(f['description'])}</p>
          <h4>Evidence</h4>
          <pre class="evidence">{html_lib.escape(f['evidence_raw'])}</pre>
          <h4>Remediation</h4>
          <p>{html_lib.escape(f['remediation'])}</p>
        </section>
        """

    summary_rows = ""
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = severity_counts.get(sev, 0)
        summary_rows += f"""
        <tr>
          <td>{_severity_badge(sev)}</td>
          <td class="count">{count}</td>
        </tr>"""

    scan_meta = {}
    if scan.get("scan_meta"):
        try:
            scan_meta = json.loads(scan["scan_meta"])
        except Exception:
            pass

    total_duration = scan_meta.get("total_duration_seconds", "N/A")
    module_durations = scan_meta.get("module_durations", {})

    timing_rows = ""
    for mod_name, dur in module_durations.items():
        timing_rows += f"""
        <tr>
          <td>{html_lib.escape(mod_name)}</td>
          <td class="count">{dur} s</td>
        </tr>"""

    timing_table_html = ""
    if module_durations:
        timing_table_html = f"""
  <h2>Execution Timings</h2>
  <table class="summary-table" style="min-width:320px">
    <thead><tr><th>Module</th><th>Elapsed Time</th></tr></thead>
    <tbody>{timing_rows}</tbody>
    <tfoot><tr><td><strong>Total Duration</strong></td><td class="count"><strong>{total_duration} s</strong></td></tr></tfoot>
  </table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel Scan Report — {html_lib.escape(scan['target_url'])}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:Inter,system-ui,sans-serif;font-size:14px;line-height:1.6;
         color:#1a2332;background:#fff;padding:40px}}
    h1{{font-size:24px;font-weight:700;color:#0F1B2D;margin-bottom:4px}}
    h2{{font-size:18px;font-weight:600;color:#0F1B2D;margin:32px 0 12px}}
    h3{{font-size:15px;font-weight:600;color:#0F1B2D;margin-bottom:8px;display:flex;align-items:center;gap:8px}}
    h4{{font-size:13px;font-weight:600;color:#374151;margin:14px 0 4px}}
    p{{margin-bottom:8px;color:#374151}}
    code{{font-family:ui-monospace,monospace;font-size:12px;background:#f3f4f6;
          padding:1px 4px;border-radius:3px}}
    pre.evidence{{font-family:ui-monospace,monospace;font-size:11px;background:#f8f9fa;
                 border:1px solid #e5e7eb;padding:12px;border-radius:4px;
                 white-space:pre-wrap;word-break:break-all;overflow-x:auto;
                 color:#374151;margin-bottom:8px}}
    .hash{{font-size:11px;word-break:break-all}}
    .badge{{display:inline-block;padding:2px 8px;border-radius:3px;
            font-size:11px;font-weight:600;letter-spacing:.03em}}
    .badge-critical{{background:#1a0000;color:#fff}}
    .badge-high{{background:#450a0a;color:#fff}}
    .badge-medium{{background:#78350f;color:#fff}}
    .badge-low{{background:#1e3a5f;color:#fff}}
    .badge-info{{background:#374151;color:#fff}}
    .meta-table{{width:100%;border-collapse:collapse;margin-bottom:12px;font-size:13px}}
    .meta-table th,.meta-table td{{padding:5px 8px;border:1px solid #e5e7eb;text-align:left}}
    .meta-table th{{background:#f9fafb;font-weight:600;width:160px;color:#374151}}
    .summary-table{{border-collapse:collapse;margin-bottom:16px}}
    .summary-table td{{padding:4px 12px;border:1px solid #e5e7eb}}
    .summary-table .count{{font-weight:700;text-align:right}}
    .finding{{border:1px solid #e5e7eb;border-radius:6px;padding:20px;
              margin-bottom:20px;page-break-inside:avoid}}
    .header-block{{border-bottom:2px solid #0F1B2D;padding-bottom:12px;margin-bottom:24px}}
    .meta-line{{font-size:12px;color:#6b7280;margin-top:4px}}
    .ledger-box{{background:#f0f9ff;border:1px solid #bae6fd;border-radius:4px;
                padding:10px 14px;font-size:12px;margin-top:8px}}
    .ledger-box code{{background:transparent;font-size:11px}}
    .num{{color:#6b7280;font-weight:400}}
    @media print{{
      body{{padding:20px}}
      .finding{{page-break-inside:avoid}}
    }}
  </style>
</head>
<body>
  <div class="header-block">
    <h1>Sentinel Scan — Vulnerability Report</h1>
    <div class="meta-line">
      Target: <strong>{html_lib.escape(scan['target_url'])}</strong> &nbsp;|&nbsp;
      Scan ID: #{scan['id']} &nbsp;|&nbsp;
      Started: {html_lib.escape(scan['started_at'] or '')} &nbsp;|&nbsp;
      Finished: {html_lib.escape(scan['finished_at'] or 'N/A')} &nbsp;|&nbsp;
      Authorized: {'Yes' if scan['authorized'] else 'Localhost / private network'}
    </div>
    <div class="meta-line">Report generated: {generated_at}</div>
  </div>

  <h2>Executive Summary</h2>
  <table class="summary-table">
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{summary_rows}</tbody>
    <tfoot><tr><td><strong>Total</strong></td><td class="count"><strong>{len(findings)}</strong></td></tr></tfoot>
  </table>
{timing_table_html}

  <div class="ledger-box">
    <strong>Forensic Ledger Tail Hash (SHA-256)</strong><br>
    <code>{html_lib.escape(tail_hash)}</code><br>
    <span style="color:#374151">This hash summarises the entire evidence chain for this scan. 
    Any post-hoc tampering with the database will cause the integrity check to fail.</span>
  </div>

  <h2>Findings</h2>
  {findings_html if findings_html else '<p>No findings recorded for this scan.</p>'}

  <hr style="margin:40px 0;border:none;border-top:1px solid #e5e7eb">
  <p style="font-size:11px;color:#9ca3af;text-align:center">
    Generated by Sentinel Scan v1.0.0 — rule-based vulnerability scanner —
    for authorised testing only
  </p>
</body>
</html>"""
