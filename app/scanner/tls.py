"""
app/scanner/tls.py

TLS and certificate scanner module.

Checks:
  - Certificate expiry (expired or expiring within 30 days)
  - Protocol version (TLSv1.0 / TLSv1.1 are deprecated)
  - Self-signed certificate detection
  - Certificate / hostname mismatch

Only runs against https:// targets.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from urllib.parse import urlparse

import requests

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A02 Cryptographic Failures"
EXPIRY_WARNING_DAYS = 30


def _get_cert_info(hostname: str, port: int) -> dict:
    """
    Open a raw TLS connection and collect certificate details.
    Returns a dict with keys: subject, issuer, not_after, protocol, error.
    """
    ctx = ssl.create_default_context()
    # Allow inspection even if cert is invalid (we report it as a finding)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result = {
        "subject": {},
        "issuer": {},
        "not_after": None,
        "protocol": None,
        "is_self_signed": False,
        "hostname_match": True,
        "error": None,
    }

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["protocol"] = ssock.version()
                cert = ssock.getpeercert()
                if cert:
                    # subject and issuer are tuples of tuples
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))

                    not_after_str = cert.get("notAfter", "")
                    if not_after_str:
                        result["not_after"] = datetime.datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=datetime.timezone.utc)

                    # Self-signed: subject == issuer
                    result["is_self_signed"] = result["subject"] == result["issuer"]

                    # Hostname check
                    try:
                        ssl.match_hostname(cert, hostname)  # type: ignore[attr-defined]
                    except ssl.CertificateError:
                        result["hostname_match"] = False
    except Exception as exc:
        result["error"] = str(exc)

    return result


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Inspect the TLS configuration of an https:// target.
    Returns a list of Finding objects.
    """
    findings: list[Finding] = []

    if not url.startswith("https://"):
        return findings  # TLS checks do not apply to plain HTTP

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    cert_info = _get_cert_info(hostname, port)

    # Build a brief evidence block shared across TLS findings
    base_evidence_notes = (
        f"Host: {hostname}:{port}\n"
        f"Protocol: {cert_info['protocol'] or 'unknown'}\n"
        f"Subject: {cert_info['subject']}\n"
        f"Issuer:  {cert_info['issuer']}\n"
        f"Not After: {cert_info['not_after']}\n"
        f"Self-signed: {cert_info['is_self_signed']}\n"
        f"Hostname match: {cert_info['hostname_match']}\n"
    )
    if cert_info["error"]:
        base_evidence_notes += f"TLS error: {cert_info['error']}\n"

    def _make_evidence(extra_note: str) -> str:
        return build_evidence(
            method="TLS_HANDSHAKE",
            url=url,
            request_headers={},
            request_body=None,
            status_code=0,
            response_headers={},
            response_excerpt="(raw TLS handshake — no HTTP body)",
            notes=base_evidence_notes + extra_note,
        )

    # -- Expired or expiring certificate --
    if cert_info["not_after"]:
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (cert_info["not_after"] - now).days
        if days_left < 0:
            findings.append(Finding(
                title="TLS Certificate Expired",
                category=OWASP_CATEGORY,
                severity="Critical",
                affected_url=url,
                description=(
                    f"The TLS certificate for {hostname} expired "
                    f"{abs(days_left)} day(s) ago "
                    f"(expired: {cert_info['not_after'].strftime('%Y-%m-%d')})."
                ),
                evidence_raw=_make_evidence(f"Certificate expired {abs(days_left)} day(s) ago."),
                remediation=(
                    "Renew the TLS certificate immediately. Use a CA such as Let's Encrypt "
                    "for free, automatically renewing certificates."
                ),
            ))
        elif days_left < EXPIRY_WARNING_DAYS:
            findings.append(Finding(
                title="TLS Certificate Expiring Soon",
                category=OWASP_CATEGORY,
                severity="High",
                affected_url=url,
                description=(
                    f"The TLS certificate for {hostname} expires in {days_left} day(s) "
                    f"({cert_info['not_after'].strftime('%Y-%m-%d')}). "
                    "An expired certificate will cause browser warnings and broken connections."
                ),
                evidence_raw=_make_evidence(f"Certificate expires in {days_left} day(s)."),
                remediation=(
                    "Renew the certificate before it expires. Consider automating renewal "
                    "with a tool such as Certbot (Let's Encrypt)."
                ),
            ))

    # -- Self-signed certificate --
    if cert_info["is_self_signed"]:
        findings.append(Finding(
            title="Self-Signed TLS Certificate",
            category=OWASP_CATEGORY,
            severity="High",
            affected_url=url,
            description=(
                f"The TLS certificate for {hostname} is self-signed. "
                "Browsers will display a security warning, and clients cannot verify "
                "the server's identity against a trusted Certificate Authority."
            ),
            evidence_raw=_make_evidence("Certificate subject equals issuer (self-signed)."),
            remediation=(
                "Replace the self-signed certificate with one issued by a trusted CA. "
                "Let's Encrypt provides free, trusted certificates via ACME automation."
            ),
        ))

    # -- Weak protocol --
    weak_protocols = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
    if cert_info["protocol"] in weak_protocols:
        findings.append(Finding(
            title=f"Deprecated TLS Protocol in Use ({cert_info['protocol']})",
            category=OWASP_CATEGORY,
            severity="High",
            affected_url=url,
            description=(
                f"The server negotiated {cert_info['protocol']}, which is deprecated "
                "and contains known vulnerabilities (e.g. POODLE, BEAST). "
                "Modern clients should use TLS 1.2 or TLS 1.3 only."
            ),
            evidence_raw=_make_evidence(f"Negotiated protocol: {cert_info['protocol']}"),
            remediation=(
                "Disable TLS 1.0 and 1.1 in your web server configuration. "
                "For nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "For Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
        ))

    # -- Hostname mismatch --
    if not cert_info["hostname_match"]:
        findings.append(Finding(
            title="TLS Certificate Hostname Mismatch",
            category=OWASP_CATEGORY,
            severity="High",
            affected_url=url,
            description=(
                f"The TLS certificate is not valid for the hostname '{hostname}'. "
                "This could indicate a misconfiguration or a man-in-the-middle attack."
            ),
            evidence_raw=_make_evidence(f"Hostname '{hostname}' does not match certificate."),
            remediation=(
                "Obtain a certificate that includes the correct hostname in its CN or "
                "Subject Alternative Names field."
            ),
        ))

    return findings
