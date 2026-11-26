"""
app/scanner/cookies.py

Cookie flag scanner module.

For every Set-Cookie header in the response, checks for:
  - Secure flag (cookie should not be sent over plain HTTP)
  - HttpOnly flag (cookie should not be accessible from JavaScript)
  - SameSite attribute (CSRF mitigation)
"""

from __future__ import annotations

import requests

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A02 Cryptographic Failures"


def _parse_cookie_flags(cookie_header: str) -> dict:
    """
    Parse a single Set-Cookie header value.
    Returns a dict with keys: name, secure, httponly, samesite.
    """
    parts = [p.strip() for p in cookie_header.split(";")]
    name = parts[0].split("=")[0].strip() if parts else "unknown"

    flags = {
        "name": name,
        "secure": False,
        "httponly": False,
        "samesite": None,
    }

    for part in parts[1:]:
        lower = part.lower()
        if lower == "secure":
            flags["secure"] = True
        elif lower == "httponly":
            flags["httponly"] = True
        elif lower.startswith("samesite="):
            flags["samesite"] = part.split("=", 1)[1].strip()

    return flags


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Fetch the target URL and inspect every Set-Cookie header.
    Returns one Finding per missing flag per cookie.
    """
    findings: list[Finding] = []
    is_https = url.startswith("https://")

    try:
        response = session.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException:
        return findings

    # requests merges repeated headers; use the raw response to get all Set-Cookie
    raw_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not raw_cookies:
        # Fallback: urllib3 may store them differently
        raw_cookies = [
            v for k, v in response.headers.items() if k.lower() == "set-cookie"
        ]

    request_info = {"headers": dict(response.request.headers) if response.request else {}}
    response_info = {
        "status_code": response.status_code,
        "body_excerpt": response.text[:500],
    }

    for cookie_header in raw_cookies:
        flags = _parse_cookie_flags(cookie_header)
        name = flags["name"]

        # -- Secure flag --
        if is_https and not flags["secure"]:
            evidence = build_evidence(
                method="GET",
                url=url,
                request_headers=request_info["headers"],
                request_body=None,
                status_code=response_info["status_code"],
                response_headers=dict(response.headers),
                response_excerpt=response_info["body_excerpt"],
                notes=(
                    f"Cookie '{name}' is set without the Secure flag.\n"
                    f"Full Set-Cookie header: {cookie_header}"
                ),
            )
            findings.append(Finding(
                title=f"Cookie '{name}' Missing Secure Flag",
                category=OWASP_CATEGORY,
                severity="Medium",
                affected_url=url,
                description=(
                    f"The cookie '{name}' is served over HTTPS but does not carry the "
                    "Secure flag. Without this flag the browser may transmit the cookie "
                    "over an unencrypted HTTP connection, exposing it to network eavesdroppers."
                ),
                evidence_raw=evidence,
                remediation=(
                    f"Set the Secure attribute on the '{name}' cookie. "
                    "Example: Set-Cookie: session=value; Secure; HttpOnly; SameSite=Strict"
                ),
            ))

        # -- HttpOnly flag --
        if not flags["httponly"]:
            evidence = build_evidence(
                method="GET",
                url=url,
                request_headers=request_info["headers"],
                request_body=None,
                status_code=response_info["status_code"],
                response_headers=dict(response.headers),
                response_excerpt=response_info["body_excerpt"],
                notes=(
                    f"Cookie '{name}' is set without the HttpOnly flag.\n"
                    f"Full Set-Cookie header: {cookie_header}"
                ),
            )
            findings.append(Finding(
                title=f"Cookie '{name}' Missing HttpOnly Flag",
                category=OWASP_CATEGORY,
                severity="Medium",
                affected_url=url,
                description=(
                    f"The cookie '{name}' does not carry the HttpOnly flag. "
                    "Without this flag, client-side JavaScript can read the cookie, "
                    "making it vulnerable to theft via cross-site scripting (XSS)."
                ),
                evidence_raw=evidence,
                remediation=(
                    f"Add the HttpOnly attribute to the '{name}' cookie. "
                    "Example: Set-Cookie: session=value; Secure; HttpOnly; SameSite=Strict"
                ),
            ))

        # -- SameSite attribute --
        if not flags["samesite"]:
            evidence = build_evidence(
                method="GET",
                url=url,
                request_headers=request_info["headers"],
                request_body=None,
                status_code=response_info["status_code"],
                response_headers=dict(response.headers),
                response_excerpt=response_info["body_excerpt"],
                notes=(
                    f"Cookie '{name}' is set without a SameSite attribute.\n"
                    f"Full Set-Cookie header: {cookie_header}"
                ),
            )
            findings.append(Finding(
                title=f"Cookie '{name}' Missing SameSite Attribute",
                category=OWASP_CATEGORY,
                severity="Low",
                affected_url=url,
                description=(
                    f"The cookie '{name}' has no SameSite attribute. "
                    "Without SameSite=Strict or SameSite=Lax, the browser will send "
                    "this cookie with cross-site requests, increasing CSRF risk."
                ),
                evidence_raw=evidence,
                remediation=(
                    f"Add SameSite=Strict (or SameSite=Lax) to the '{name}' cookie. "
                    "SameSite=Strict provides the strongest protection; use Lax if "
                    "top-level navigations must carry the cookie."
                ),
            ))

    return findings
