"""
app/scanner/cors.py

CORS misconfiguration scanner module.

Tests for two classes of CORS vulnerabilities:
  1. Wildcard origin: Access-Control-Allow-Origin: *
     — credentials cannot be sent in this case, but public APIs may still
       disclose sensitive data.
  2. Reflected/arbitrary origin: the server echoes back whatever Origin
     header the request sends.
     — combined with Access-Control-Allow-Credentials: true this is Critical.

The module sends GET requests with two crafted Origin values and inspects the
reflected Access-Control-Allow-Origin header.
"""

from __future__ import annotations

import requests

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A01 Broken Access Control"

# Two probe origins: one plausible attacker domain, one that should never match
PROBE_ORIGINS = [
    "https://evil.example.com",
    "https://attacker-sentinel-probe.invalid",
]


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Send crafted Origin headers and inspect the CORS response headers.
    Returns a list of Finding objects.
    """
    findings: list[Finding] = []

    # First, make a plain request to check for wildcard origin
    try:
        plain_response = session.get(url, timeout=10)
    except requests.RequestException:
        return findings

    acao = plain_response.headers.get("Access-Control-Allow-Origin", "")
    acac = plain_response.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*":
        evidence = build_evidence(
            method="GET",
            url=url,
            request_headers=dict(plain_response.request.headers) if plain_response.request else {},
            request_body=None,
            status_code=plain_response.status_code,
            response_headers=dict(plain_response.headers),
            response_excerpt=plain_response.text[:1000],
            notes=(
                "Access-Control-Allow-Origin: * was returned on a plain GET request.\n"
                "Any origin on the internet can read responses from this endpoint."
            ),
        )
        findings.append(Finding(
            title="CORS Wildcard Origin (Access-Control-Allow-Origin: *)",
            category=OWASP_CATEGORY,
            severity="Medium",
            affected_url=url,
            description=(
                "The server responds with 'Access-Control-Allow-Origin: *', which allows "
                "any website to make cross-origin requests and read the response. "
                "If this endpoint returns sensitive data it should restrict the allowed origins."
            ),
            evidence_raw=evidence,
            remediation=(
                "Replace the wildcard with an explicit allowlist of trusted origins. "
                "Example: Access-Control-Allow-Origin: https://www.yourdomain.com  "
                "Never combine Access-Control-Allow-Origin: * with "
                "Access-Control-Allow-Credentials: true."
            ),
        ))

    # Next, probe with crafted Origin headers to test for reflection
    for probe_origin in PROBE_ORIGINS:
        try:
            headers_to_send = {"Origin": probe_origin}
            response = session.get(url, headers=headers_to_send, timeout=10)
        except requests.RequestException:
            continue

        reflected_origin = response.headers.get("Access-Control-Allow-Origin", "")
        allows_creds = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if reflected_origin == probe_origin:
            # Server is blindly reflecting our crafted Origin
            severity = "Critical" if allows_creds else "High"

            notes = (
                f"Probe Origin sent: {probe_origin}\n"
                f"Reflected Access-Control-Allow-Origin: {reflected_origin}\n"
                f"Access-Control-Allow-Credentials: {allows_creds}\n\n"
                + (
                    "CRITICAL: Credentials flag is true. An attacker page can send "
                    "credentialed cross-origin requests and read the response."
                    if allows_creds
                    else "An attacker page can read responses from this endpoint."
                )
            )

            evidence = build_evidence(
                method="GET",
                url=url,
                request_headers={**dict(response.request.headers if response.request else {}), "Origin": probe_origin},
                request_body=None,
                status_code=response.status_code,
                response_headers=dict(response.headers),
                response_excerpt=response.text[:1000],
                notes=notes,
            )

            findings.append(Finding(
                title="CORS Misconfiguration: Arbitrary Origin Reflected"
                + (" with Credentials" if allows_creds else ""),
                category=OWASP_CATEGORY,
                severity=severity,
                affected_url=url,
                description=(
                    f"The server reflects the caller's Origin header back in "
                    f"Access-Control-Allow-Origin. When tested with '{probe_origin}', "
                    f"the response included 'Access-Control-Allow-Origin: {reflected_origin}'. "
                    + (
                        "Combined with 'Access-Control-Allow-Credentials: true', this allows "
                        "a malicious website to make authenticated cross-origin requests and "
                        "read the full response — a Critical CORS vulnerability."
                        if allows_creds
                        else "This allows any website to read responses from this endpoint."
                    )
                ),
                evidence_raw=evidence,
                remediation=(
                    "Do not reflect the Origin header without validation. "
                    "Maintain an explicit allowlist of permitted origins and reject all others. "
                    "Never set Access-Control-Allow-Credentials: true with a dynamically "
                    "reflected or wildcard origin."
                ),
            ))
            break  # One reflection finding is enough; avoid duplicate reports

    return findings
