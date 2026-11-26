"""
app/scanner/headers.py

Security HTTP headers scanner module.

Checks for the presence and minimal correctness of:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
"""

from __future__ import annotations

from typing import Optional
import requests

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A05 Security Misconfiguration"


def _check(
    header_name: str,
    headers: dict,
    url: str,
    request_info: dict,
    response_info: dict,
) -> Optional[Finding]:
    """Return a Finding if the given header is absent, else None."""
    # Normalise header names to lowercase for case-insensitive lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}
    name_lower = header_name.lower()

    if name_lower not in lower_headers:
        evidence = build_evidence(
            method="GET",
            url=url,
            request_headers=request_info["headers"],
            request_body=None,
            status_code=response_info["status_code"],
            response_headers=headers,
            response_excerpt=response_info["body_excerpt"],
            notes=f"Header '{header_name}' was not present in the HTTP response.",
        )
        return Finding(
            title=f"Missing {header_name} Header",
            category=OWASP_CATEGORY,
            severity=_severity(header_name),
            affected_url=url,
            description=(
                f"The HTTP response does not include the '{header_name}' security "
                f"header. {_description(header_name)}"
            ),
            evidence_raw=evidence,
            remediation=_remediation(header_name),
        )
    return None


def _severity(header_name: str) -> str:
    high = {"Content-Security-Policy", "Strict-Transport-Security"}
    medium = {"X-Frame-Options", "X-Content-Type-Options"}
    if header_name in high:
        return "High"
    if header_name in medium:
        return "Medium"
    return "Low"


def _description(header_name: str) -> str:
    descriptions = {
        "Content-Security-Policy": (
            "CSP restricts which resources the browser is permitted to load, "
            "mitigating XSS and data injection attacks."
        ),
        "Strict-Transport-Security": (
            "HSTS forces browsers to connect over HTTPS only, preventing "
            "protocol downgrade and man-in-the-middle attacks."
        ),
        "X-Frame-Options": (
            "This header prevents the page from being embedded in an iframe, "
            "defending against clickjacking attacks."
        ),
        "X-Content-Type-Options": (
            "Setting this to 'nosniff' stops browsers from MIME-sniffing "
            "responses away from the declared content type."
        ),
        "Referrer-Policy": (
            "Controls how much referrer information is sent with requests, "
            "reducing information leakage to third parties."
        ),
        "Permissions-Policy": (
            "Restricts which browser features (camera, microphone, etc.) "
            "the page and embedded iframes may use."
        ),
    }
    return descriptions.get(header_name, "")


def _remediation(header_name: str) -> str:
    remediations = {
        "Content-Security-Policy": (
            "Add a Content-Security-Policy header to your web server or application. "
            "Start with a strict policy such as: "
            "\"default-src 'self'\" and loosen only as needed. "
            "Refer to https://content-security-policy.com for guidance."
        ),
        "Strict-Transport-Security": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains "
            "to your HTTPS responses. Ensure your site is fully HTTPS before enabling."
        ),
        "X-Frame-Options": (
            "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN "
            "to prevent framing by malicious sites."
        ),
        "X-Content-Type-Options": (
            "Add: X-Content-Type-Options: nosniff to all responses."
        ),
        "Referrer-Policy": (
            "Add: Referrer-Policy: strict-origin-when-cross-origin "
            "(or a stricter value) to control referrer leakage."
        ),
        "Permissions-Policy": (
            "Add a Permissions-Policy header listing only the features your "
            "application actually uses. Example: Permissions-Policy: geolocation=(), "
            "camera=(), microphone=()"
        ),
    }
    return remediations.get(header_name, f"Add the {header_name} header.")


CHECKED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Fetch the target URL and check for missing security headers.
    Returns one Finding per absent header.
    """
    findings: list[Finding] = []

    try:
        response = session.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        return findings  # Errors are handled at the runner level

    request_info = {
        "headers": dict(response.request.headers) if response.request else {},
    }
    response_info = {
        "status_code": response.status_code,
        "body_excerpt": response.text[:1500],
    }

    for header in CHECKED_HEADERS:
        # Skip HSTS check for plain HTTP targets — it cannot apply
        if header == "Strict-Transport-Security" and not url.startswith("https://"):
            continue
        finding = _check(
            header,
            dict(response.headers),
            url,
            request_info,
            response_info,
        )
        if finding:
            findings.append(finding)

    return findings
