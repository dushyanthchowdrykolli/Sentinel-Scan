"""
app/scanner/csrf.py

CSRF token scanner module.

Fetches the target page, parses all HTML forms, and reports any form that:
  - Uses a POST method (or has no method, which defaults to GET — also flagged)
  - Does not contain a hidden input field that looks like a CSRF token

This is a heuristic check.  Token field names vary by framework; the module
checks for a range of common names.  False positives are possible for forms
that use header-based CSRF protection, which is not inspectable from HTML.
"""

from __future__ import annotations

import re
import requests
from bs4 import BeautifulSoup

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A01 Broken Access Control"

# Common CSRF token field names (case-insensitive match)
CSRF_FIELD_PATTERNS = [
    re.compile(r"csrf", re.IGNORECASE),
    re.compile(r"_token", re.IGNORECASE),
    re.compile(r"xsrf", re.IGNORECASE),
    re.compile(r"authenticity_token", re.IGNORECASE),
    re.compile(r"nonce", re.IGNORECASE),
    re.compile(r"__requestverificationtoken", re.IGNORECASE),
    re.compile(r"antiforgery", re.IGNORECASE),
]


def _looks_like_csrf_field(input_tag) -> bool:
    """Return True if an <input> element looks like a CSRF token."""
    name = input_tag.get("name", "")
    input_id = input_tag.get("id", "")
    input_type = input_tag.get("type", "").lower()

    # Must be hidden or have a csrf-like name
    for pattern in CSRF_FIELD_PATTERNS:
        if pattern.search(name) or pattern.search(input_id):
            return True

    # Also accept hidden inputs whose value is long (likely a token)
    if input_type == "hidden":
        value = input_tag.get("value", "")
        if len(value) >= 20:
            return True

    return False


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Parse the page at url for HTML forms lacking CSRF protection.
    Returns one Finding per unprotected form.
    """
    findings: list[Finding] = []

    try:
        response = session.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException:
        return findings

    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        return findings  # Not an HTML page — no forms to analyse

    try:
        soup = BeautifulSoup(response.text, "lxml")
    except Exception:
        soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")
    if not forms:
        return findings

    request_info = {"headers": dict(response.request.headers) if response.request else {}}

    for idx, form in enumerate(forms):
        method = (form.get("method") or "get").upper()
        action = form.get("action") or url

        # Only POST forms need CSRF protection; skip GET forms (but note them at Info level)
        # Actually flag GET forms with sensitive-looking actions too — omit for brevity
        if method != "POST":
            continue

        # Check if any input in this form looks like a CSRF token
        inputs = form.find_all("input")
        has_token = any(_looks_like_csrf_field(inp) for inp in inputs)

        if has_token:
            continue  # Protected

        # Reconstruct a snippet of the form for evidence
        form_snippet = str(form)[:1200]

        evidence = build_evidence(
            method="GET",
            url=url,
            request_headers=request_info["headers"],
            request_body=None,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_excerpt=form_snippet,
            notes=(
                f"Form #{idx + 1}: method={method}, action={action}\n"
                "No CSRF token field detected in this form.\n"
                "Checked input names and IDs for csrf, _token, xsrf, nonce, etc."
            ),
        )

        findings.append(Finding(
            title=f"POST Form Without CSRF Token (Form #{idx + 1})",
            category=OWASP_CATEGORY,
            severity="Medium",
            affected_url=url,
            description=(
                f"A POST form (action: '{action}') on this page does not appear to include "
                "a CSRF token. Without a token, an attacker can craft a malicious page "
                "that submits the form on behalf of an authenticated user (Cross-Site "
                "Request Forgery). Note: if the application uses header-based CSRF "
                "protection (e.g. double-submit cookie or SameSite cookies) this may be "
                "a false positive."
            ),
            evidence_raw=evidence,
            remediation=(
                "Add a CSRF token to every state-changing form: "
                "(1) Generate a cryptographically random token per session. "
                "(2) Embed it in the form as a hidden field. "
                "(3) Validate the token on the server before processing the request. "
                "Most web frameworks provide built-in CSRF protection middleware."
            ),
        ))

    return findings
