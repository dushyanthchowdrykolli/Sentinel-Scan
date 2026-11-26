"""
app/scanner/banners.py

Server and technology banner disclosure scanner module.

Checks response headers for information that reveals the web server name,
version, framework, language, or other backend technology.  Disclosed versions
help attackers identify known CVEs quickly.

Inspected headers:
  - Server
  - X-Powered-By
  - X-AspNet-Version
  - X-AspNetMvc-Version
  - X-Generator
  - Via
"""

from __future__ import annotations

import re
import requests

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A05 Security Misconfiguration"

# Headers that commonly leak technology information
BANNER_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
]

# Regex to detect version strings like "Apache/2.4.51" or "PHP/8.1.0"
VERSION_RE = re.compile(r"[\d]+\.[\d]+")


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Fetch the target URL and inspect response headers for technology banners.
    Returns one Finding per disclosed banner header.
    """
    findings: list[Finding] = []

    try:
        response = session.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException:
        return findings

    request_info = {"headers": dict(response.request.headers) if response.request else {}}
    response_info = {
        "status_code": response.status_code,
        "body_excerpt": response.text[:500],
    }

    for header_name in BANNER_HEADERS:
        # Case-insensitive lookup
        value = response.headers.get(header_name) or response.headers.get(header_name.lower())
        if not value:
            continue

        has_version = bool(VERSION_RE.search(value))
        severity = "Medium" if has_version else "Low"

        evidence = build_evidence(
            method="GET",
            url=url,
            request_headers=request_info["headers"],
            request_body=None,
            status_code=response_info["status_code"],
            response_headers=dict(response.headers),
            response_excerpt=response_info["body_excerpt"],
            notes=(
                f"Disclosed header: {header_name}: {value}\n"
                f"Contains version string: {has_version}"
            ),
        )

        findings.append(Finding(
            title=f"Technology Banner Disclosed via {header_name}",
            category=OWASP_CATEGORY,
            severity=severity,
            affected_url=url,
            description=(
                f"The response header '{header_name}' reveals backend technology details: "
                f"'{value}'. "
                + (
                    "A specific version number is disclosed, which helps attackers "
                    "quickly look up known vulnerabilities (CVEs) for that version. "
                    if has_version
                    else "Even without a version number, disclosing the technology stack "
                    "assists attackers in fingerprinting the application. "
                )
            ),
            evidence_raw=evidence,
            remediation=(
                f"Remove or suppress the '{header_name}' header in your web server or "
                "application configuration. "
                "For nginx: 'server_tokens off;'  "
                "For Apache: 'ServerTokens Prod' and 'ServerSignature Off'  "
                "For Express.js: 'app.disable(\"x-powered-by\");'"
            ),
        ))

    return findings
