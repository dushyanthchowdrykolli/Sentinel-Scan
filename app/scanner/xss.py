"""
app/scanner/xss.py

Reflected XSS probe scanner module.

Strategy:
  - Find all URL parameters on the target page (from query strings and HTML forms)
  - Inject a harmless, unique marker string as the parameter value
  - Check whether that exact marker string appears unencoded in the response body
  - If it does, the parameter is likely reflected without encoding — a strong
    indicator of reflected XSS

The probe string uses only alphanumeric characters and a unique sentinel prefix.
No actual script execution payloads (e.g. <script>) are sent.  This is purely
a detection probe, not exploitation.
"""

from __future__ import annotations

import re
import uuid
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A03 Injection"

# The marker is a UUID-based string that is extremely unlikely to appear naturally.
# It contains no HTML special characters, so it cannot trigger script execution.
PROBE_PREFIX = "SNTLXSS"


def _make_probe_value() -> str:
    return PROBE_PREFIX + uuid.uuid4().hex[:8].upper()


def _get_url_params(url: str) -> dict:
    """Extract query string parameters from a URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def _replace_param(url: str, param_name: str, probe: str) -> str:
    """Return a new URL with the specified parameter replaced by the probe value."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [probe]
    new_query = urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _get_form_params(soup: BeautifulSoup) -> list[dict]:
    """
    Extract all form action URLs and their input field names.
    Returns a list of dicts with keys: action, method, fields.
    """
    results = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").upper()
        action = form.get("action") or ""
        fields = []
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name and inp.get("type", "text").lower() not in ("submit", "button", "hidden", "file", "image", "reset", "checkbox", "radio"):
                fields.append(name)
        for textarea in form.find_all("textarea"):
            name = textarea.get("name")
            if name:
                fields.append(name)
        if fields:
            results.append({"action": action, "method": method, "fields": fields})
    return results


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Probe URL parameters and form fields for reflected XSS.
    Returns a Finding for each parameter that reflects the probe string unencoded.
    """
    findings: list[Finding] = []
    seen_params: set[str] = set()

    # Fetch the base page
    try:
        base_response = session.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException:
        return findings

    content_type = base_response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        return findings

    try:
        soup = BeautifulSoup(base_response.text, "lxml")
    except Exception:
        soup = BeautifulSoup(base_response.text, "html.parser")

    # Collect parameters to test: from URL query string
    url_params = _get_url_params(url)
    for param_name in url_params:
        if param_name in seen_params:
            continue
        seen_params.add(param_name)

        probe = _make_probe_value()
        probe_url = _replace_param(url, param_name, probe)

        try:
            resp = session.get(probe_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            continue

        # Check for unencoded reflection
        if probe in resp.text:
            # Verify the probe is not HTML-encoded
            encoded_forms = [
                probe.replace("S", "&#83;"),
                "&amp;".join(probe),  # rough check
            ]
            if not any(ef in resp.text for ef in encoded_forms):
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
                        f"Probe value: {probe}\n"
                        f"Probe found unencoded in response body.\n"
                        "This strongly indicates reflected XSS vulnerability."
                    ),
                )
                findings.append(Finding(
                    title=f"Reflected XSS Probe Reflected: Parameter '{param_name}'",
                    category=OWASP_CATEGORY,
                    severity="High",
                    affected_url=probe_url,
                    description=(
                        f"The URL parameter '{param_name}' reflects input directly "
                        f"into the HTML response without encoding. The probe string "
                        f"'{probe}' was found verbatim in the response body. "
                        "An attacker can craft a URL that injects arbitrary HTML or "
                        "JavaScript, which executes in the victim's browser."
                    ),
                    evidence_raw=evidence,
                    remediation=(
                        "Encode all user-supplied data before rendering it in HTML. "
                        "Use context-aware output encoding: HTML-encode for HTML context, "
                        "JavaScript-encode for script context, URL-encode for URLs. "
                        "Implement a Content-Security-Policy header as a defence-in-depth measure."
                    ),
                ))

    # Collect parameters from forms (GET forms only for safety; POST would mutate state)
    form_params = _get_form_params(soup)
    for form_info in form_params:
        if form_info["method"] != "GET":
            continue
        action = form_info["action"] or url
        # Resolve relative action URL
        if not action.startswith("http"):
            action = urljoin(url, action)

        for field_name in form_info["fields"]:
            if field_name in seen_params:
                continue
            seen_params.add(field_name)

            probe = _make_probe_value()
            probe_url = _replace_param(action, field_name, probe)

            try:
                resp = session.get(probe_url, timeout=10, allow_redirects=True)
            except requests.RequestException:
                continue

            if probe in resp.text:
                evidence = build_evidence(
                    method="GET",
                    url=probe_url,
                    request_headers=dict(resp.request.headers) if resp.request else {},
                    request_body=None,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_excerpt=resp.text[:2000],
                    notes=(
                        f"Form field: {field_name}\n"
                        f"Form action: {action}\n"
                        f"Probe value: {probe}\n"
                        "Probe found unencoded in response body."
                    ),
                )
                findings.append(Finding(
                    title=f"Reflected XSS Probe Reflected: Form Field '{field_name}'",
                    category=OWASP_CATEGORY,
                    severity="High",
                    affected_url=probe_url,
                    description=(
                        f"The form field '{field_name}' (action: '{action}') reflects "
                        f"input directly into the HTML response without encoding. "
                        f"The probe string '{probe}' was found verbatim in the response body."
                    ),
                    evidence_raw=evidence,
                    remediation=(
                        "Apply output encoding to all user-controlled values before "
                        "rendering them in HTML. Use framework-provided escaping functions."
                    ),
                ))

    return findings
