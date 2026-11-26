"""
app/scanner/sqli.py

SQL injection probe scanner module.

Detection strategy (read-only, error-based only):
  1. Single-quote injection: append a single quote to each parameter value and
     look for database error messages in the response.
  2. Boolean-style: compare response length/content between param=value and
     param=value AND 1=1 vs param=value AND 1=2.  A significant content
     difference suggests the parameter is interpreted by SQL.

No data is extracted.  Payloads are minimal and cannot cause data loss or
modification on a standard read-only SELECT query.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import requests
from bs4 import BeautifulSoup

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A03 Injection"

# Common database error message fragments (case-insensitive)
DB_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"pg_query\(\):", re.IGNORECASE),
    re.compile(r"sqlite3\.operationalerror", re.IGNORECASE),
    re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE),
    re.compile(r"odbc sql server driver", re.IGNORECASE),
    re.compile(r"ora-\d{5}", re.IGNORECASE),
    re.compile(r"syntax error.*near", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"unterminated string literal", re.IGNORECASE),
    re.compile(r"sqliteexception", re.IGNORECASE),
    re.compile(r"sqlexception", re.IGNORECASE),
    re.compile(r"db2 sql error", re.IGNORECASE),
]


def _get_url_params(url: str) -> dict:
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def _replace_param(url: str, param_name: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [value]
    new_query = urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _has_db_error(text: str) -> tuple[bool, str]:
    """Return (True, matched_pattern_string) if a DB error is found in text."""
    for pattern in DB_ERROR_PATTERNS:
        m = pattern.search(text)
        if m:
            return True, m.group(0)
    return False, ""


def _get_form_get_params(soup: BeautifulSoup, base_url: str) -> list[dict]:
    """Extract GET form field names for probing."""
    results = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").upper()
        if method != "GET":
            continue
        action = form.get("action") or base_url
        if not action.startswith("http"):
            action = urljoin(base_url, action)
        fields = []
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name and inp.get("type", "text").lower() not in (
                "submit", "button", "hidden", "file", "image", "reset", "checkbox", "radio"
            ):
                default_val = inp.get("value") or "1"
                fields.append((name, default_val))
        if fields:
            results.append({"action": action, "fields": fields})
    return results


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Probe URL and form parameters for SQL injection indicators.
    Returns a Finding per parameter that shows DB error patterns or boolean response differences.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    # Fetch base page
    try:
        base_resp = session.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException:
        return findings

    content_type = base_resp.headers.get("Content-Type", "")
    try:
        soup = BeautifulSoup(base_resp.text, "lxml")
    except Exception:
        soup = BeautifulSoup(base_resp.text, "html.parser")

    # Build a list of (probe_url_template, param_name, original_value)
    probe_targets: list[tuple[str, str, str]] = []

    # From URL query string
    for param, values in _get_url_params(url).items():
        probe_targets.append((url, param, values[0] if values else "1"))

    # From GET forms
    for form_info in _get_form_get_params(soup, url):
        action = form_info["action"]
        for field_name, default_val in form_info["fields"]:
            probe_targets.append((action, field_name, default_val))

    for base_probe_url, param_name, original_value in probe_targets:
        key = f"{base_probe_url}::{param_name}"
        if key in seen:
            continue
        seen.add(key)

        # --- Test 1: Single-quote injection ---
        sqli_value = original_value + "'"
        probe_url = _replace_param(base_probe_url, param_name, sqli_value)

        try:
            resp = session.get(probe_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            continue

        has_error, matched = _has_db_error(resp.text)

        if has_error:
            evidence = build_evidence(
                method="GET",
                url=probe_url,
                request_headers=dict(resp.request.headers) if resp.request else {},
                request_body=None,
                status_code=resp.status_code,
                response_headers=dict(resp.headers),
                response_excerpt=resp.text[:2000],
                notes=(
                    f"Parameter: {param_name}\n"
                    f"Payload: {sqli_value!r}\n"
                    f"DB error pattern matched: {matched!r}\n"
                    "A single-quote caused a database error visible in the response."
                ),
            )
            findings.append(Finding(
                title=f"SQL Injection (Error-Based): Parameter '{param_name}'",
                category=OWASP_CATEGORY,
                severity="Critical",
                affected_url=probe_url,
                description=(
                    f"The parameter '{param_name}' appears to be vulnerable to SQL injection. "
                    f"Appending a single quote to the value caused a database error message "
                    f"to appear in the response: '{matched}'. "
                    "This strongly indicates that user input is passed to a SQL query without "
                    "sanitisation or parameterisation."
                ),
                evidence_raw=evidence,
                remediation=(
                    "Use parameterised queries (prepared statements) for all database interactions. "
                    "Never concatenate user input into SQL strings. "
                    "Apply the principle of least privilege to database accounts. "
                    "Suppress detailed error messages in production responses."
                ),
            ))
            continue  # No need for boolean test if error-based already confirmed

        # --- Test 2: Boolean-style (response length comparison) ---
        try:
            url_true = _replace_param(base_probe_url, param_name, original_value + " AND 1=1")
            url_false = _replace_param(base_probe_url, param_name, original_value + " AND 1=2")
            resp_true = session.get(url_true, timeout=10, allow_redirects=True)
            resp_false = session.get(url_false, timeout=10, allow_redirects=True)
        except requests.RequestException:
            continue

        len_original = len(base_resp.text)
        len_true = len(resp_true.text)
        len_false = len(resp_false.text)

        # Heuristic: true-condition response is close to original; false is significantly different
        if len_original > 0:
            diff_true = abs(len_true - len_original) / len_original
            diff_false = abs(len_false - len_original) / len_original

            if diff_true < 0.05 and diff_false > 0.20:
                evidence = build_evidence(
                    method="GET",
                    url=url_true,
                    request_headers=dict(resp_true.request.headers) if resp_true.request else {},
                    request_body=None,
                    status_code=resp_true.status_code,
                    response_headers=dict(resp_true.headers),
                    response_excerpt=resp_true.text[:2000],
                    notes=(
                        f"Parameter: {param_name}\n"
                        f"Original response length: {len_original}\n"
                        f"AND 1=1 response length: {len_true} (diff {diff_true:.1%})\n"
                        f"AND 1=2 response length: {len_false} (diff {diff_false:.1%})\n"
                        "Boolean-style injection: false condition significantly changes response."
                    ),
                )
                findings.append(Finding(
                    title=f"SQL Injection (Boolean-Style Indicator): Parameter '{param_name}'",
                    category=OWASP_CATEGORY,
                    severity="High",
                    affected_url=url_true,
                    description=(
                        f"The parameter '{param_name}' shows a Boolean-style SQL injection "
                        f"indicator. The response length differs significantly between "
                        f"'AND 1=1' ({len_true} bytes) and 'AND 1=2' ({len_false} bytes), "
                        f"while the original response was {len_original} bytes. "
                        "This pattern suggests user input may be evaluated in a SQL expression."
                    ),
                    evidence_raw=evidence,
                    remediation=(
                        "Use parameterised queries for all database operations. "
                        "Validate and type-check all user-supplied parameters. "
                        "Apply an input allowlist where the set of valid values is known."
                    ),
                ))

    return findings
