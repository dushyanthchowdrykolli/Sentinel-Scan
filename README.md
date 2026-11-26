# Sentinel Scan

A web vulnerability scanner with forensic-grade evidence handling, built as a final-semester project for Vulnerability Analysis and Cyber Forensics.

## Overview

Sentinel Scan is a **rule-based** web vulnerability scanner. It scans one authorized target at a time, records cryptographic proof of every finding, and produces a tamper-evident report. All logic is deterministic — no machine learning or external AI APIs are used.

## Features

- **9 scanner modules**: security headers, cookie flags, TLS/certificate, banner disclosure, exposed paths, CORS misconfiguration, missing CSRF tokens, reflected XSS probe, SQL injection probe
- **Forensic evidence layer**: SHA-256 hash of every evidence item; hash-chained ledger in SQLite
- **Integrity verification**: detects any tampered ledger entry and reports the first point of divergence
- **Report export**: self-contained HTML (print-to-PDF) and JSON
- **Demo-ready lab target**: intentionally vulnerable Flask app at `lab_target/`

## Safety Controls

- By default, only `localhost`, `127.0.0.1`, and RFC-1918 private addresses are permitted
- External targets require an explicit authorization checkbox; the confirmation is logged in the ledger
- All scans are non-destructive: no exploitation, no data extraction, no brute force
- Requests are rate-limited (~5/s) with timeouts

## Requirements

- Python 3.11 or newer
- pip

## Setup

```bash
# 1. Clone or unzip the project
cd "Web Vulnerability Scanner with Evidence Reports"

# 2. Create a virtual environment (recommended)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

## Run

```bash
# Start the main application (from the project root)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Open in browser
# http://127.0.0.1:8000
```

## Demo Walkthrough

### 1. Start the lab target

Open a second terminal:

```bash
# Windows (activate venv first)
python lab_target/app.py
# Runs on http://127.0.0.1:5000
```

### 2. Run a scan

1. Open `http://127.0.0.1:8000` in your browser
2. Click **New Scan**
3. Enter `http://127.0.0.1:5000` as the target URL
4. Leave the authorization checkbox unchecked (localhost is pre-approved)
5. Click **Start Scan**
6. Watch findings arrive on the live progress screen
7. Click any finding for full evidence with its SHA-256 hash

### 3. Verify integrity

1. From the scan results screen, click **Verify Integrity**
2. The ledger chain is recomputed — all entries should pass
3. To test tamper detection: open `sentinel_scan.db` with any SQLite browser, edit the `evidence_hash` column of one row, then run Verify Integrity again — it will report the first broken link

### 4. Export report

- Click **Export HTML** for a self-contained, print-friendly report
- Click **Export JSON** for machine-readable output
- Use the browser's **Print → Save as PDF** for a PDF

## Alternative Target: DVWA via Docker

If Docker is available, you can test against DVWA (Damn Vulnerable Web Application):

```bash
docker run --rm -p 80:80 vulnerables/web-dvwa
# Target URL: http://127.0.0.1
```

DVWA has intentional XSS, SQLi, and CSRF vulnerabilities that Sentinel Scan will detect.

## Scanner Modules

| File | Module | OWASP Category |
|------|--------|----------------|
| `app/scanner/headers.py` | Security HTTP headers | A05 Security Misconfiguration |
| `app/scanner/cookies.py` | Cookie flag analysis | A02 Cryptographic Failures |
| `app/scanner/tls.py` | TLS/certificate check | A02 Cryptographic Failures |
| `app/scanner/banners.py` | Server/technology banner | A05 Security Misconfiguration |
| `app/scanner/paths.py` | Exposed paths and files | A05 Security Misconfiguration |
| `app/scanner/cors.py` | CORS misconfiguration | A01 Broken Access Control |
| `app/scanner/csrf.py` | Missing CSRF tokens | A01 Broken Access Control |
| `app/scanner/xss.py` | Reflected XSS probe | A03 Injection |
| `app/scanner/sqli.py` | SQL injection probe | A03 Injection |

## Running Tests

```bash
pytest tests/ -v
```

## Folder Structure

```
.
├── app/
│   ├── main.py              # FastAPI app, routes, static files
│   ├── database.py          # SQLite schema and helpers
│   ├── models.py            # Pydantic schemas
│   ├── evidence/
│   │   └── ledger.py        # Hash-chained ledger
│   ├── report/
│   │   └── export.py        # HTML and JSON report generation
│   └── scanner/
│       ├── runner.py        # Orchestrates all modules
│       ├── base.py          # Shared Finding schema
│       ├── headers.py
│       ├── cookies.py
│       ├── tls.py
│       ├── banners.py
│       ├── paths.py
│       ├── cors.py
│       ├── csrf.py
│       ├── xss.py
│       └── sqli.py
├── static/
│   ├── style.css
│   └── app.js
├── lab_target/
│   └── app.py               # Intentionally vulnerable Flask app
├── tests/
│   ├── test_ledger.py
│   └── test_schema.py
├── requirements.txt
└── README.md
```

## Notes

- The SQLite database (`sentinel_scan.db`) is created automatically on first run in the project root
- Evidence is stored in the database; no files are written to disk outside of exports
- The scanner respects `prefers-reduced-motion` for all CSS animations
- Keyboard navigation and visible focus states are present on all interactive elements
