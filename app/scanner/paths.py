"""
app/scanner/paths.py

Common exposed paths scanner module.

Probes a fixed list of well-known sensitive paths and reports any that return
a non-404 response.  Also checks for simple directory listing indicators.

This is purely read-only: no payloads are sent; only GET requests are made.
"""

from __future__ import annotations

import requests

from app.scanner.base import Finding, build_evidence


OWASP_CATEGORY = "A05 Security Misconfiguration"

# Paths known to expose sensitive information when accessible
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, human label, reason)
    ("/admin",        "Admin Panel",           "Administrative interface exposed publicly"),
    ("/admin/",       "Admin Panel (trailing)", "Administrative interface exposed publicly"),
    ("/.git/",        "Git Repository",         ".git directory leaks full source code history"),
    ("/.git/HEAD",    "Git HEAD file",          ".git HEAD file confirms Git repository exposure"),
    ("/.env",         ".env File",              "Environment file may contain secrets and credentials"),
    ("/backup",       "Backup Directory",       "Backup directory may contain sensitive application data"),
    ("/backup.zip",   "Backup Archive",         "Backup archive may contain the full application source"),
    ("/backup.tar.gz","Backup Archive (tar)",   "Backup archive may contain the full application source"),
    ("/robots.txt",   "Robots.txt",             "robots.txt may reveal hidden paths and admin endpoints"),
    ("/phpinfo.php",  "PHP Info Page",          "phpinfo() exposes server configuration and environment"),
    ("/server-status","Apache Server Status",   "Apache mod_status leaks request and connection details"),
    ("/web.config",   "IIS Web Config",         "web.config may contain credentials or internal paths"),
    ("/wp-admin/",    "WordPress Admin",        "WordPress admin panel exposed"),
    ("/wp-config.php","WordPress Config",       "WordPress config file may contain database credentials"),
    ("/.htaccess",    "Apache htaccess",        "htaccess file may contain rewrite rules or credentials"),
]

# Indicators in HTML body that suggest directory listing is enabled
DIR_LISTING_INDICATORS = [
    "Index of /",
    "Directory listing for",
    "Parent Directory",
    "[PARENTDIR]",
]


def _is_directory_listing(body: str) -> bool:
    lower = body.lower()
    return any(indicator.lower() in lower for indicator in DIR_LISTING_INDICATORS)


def run(url: str, session: requests.Session) -> list[Finding]:
    """
    Probe each sensitive path under the target's base URL.
    Returns one Finding per path that is accessible.
    """
    findings: list[Finding] = []

    # Strip any trailing slash from the base URL
    base = url.rstrip("/")

    for path, label, reason in SENSITIVE_PATHS:
        probe_url = base + path
        try:
            response = session.get(probe_url, timeout=10, allow_redirects=False)
        except requests.RequestException:
            continue

        status = response.status_code

        # 200 or 403 (exists but forbidden) are both notable; skip 404 and redirects
        if status in (404, 302, 301):
            continue

        body_excerpt = response.text[:1500]
        is_listing = _is_directory_listing(body_excerpt)

        notes = (
            f"Path: {path}\n"
            f"HTTP status: {status}\n"
            f"Reason: {reason}\n"
            + (f"Directory listing detected in response body." if is_listing else "")
        )

        evidence = build_evidence(
            method="GET",
            url=probe_url,
            request_headers=dict(response.request.headers) if response.request else {},
            request_body=None,
            status_code=status,
            response_headers=dict(response.headers),
            response_excerpt=body_excerpt,
            notes=notes,
        )

        severity = "High"
        if path in ("/.git/", "/.git/HEAD", "/.env", "/backup.zip", "/backup.tar.gz", "/wp-config.php"):
            severity = "Critical"
        elif status == 403:
            severity = "Low"  # Exists but access-controlled

        title = f"Sensitive Path Accessible: {label}"
        if is_listing:
            title = f"Directory Listing Enabled: {label}"

        description = (
            f"The path '{path}' responded with HTTP {status}. {reason}. "
        )
        if status == 403:
            description += (
                "Although access is currently forbidden, the resource exists on the server. "
                "Authorisation controls should be reviewed to ensure they are robust."
            )
        if is_listing:
            description += (
                " The response body indicates that directory listing is enabled, "
                "allowing enumeration of all files in this directory."
            )

        findings.append(Finding(
            title=title,
            category=OWASP_CATEGORY,
            severity=severity,
            affected_url=probe_url,
            description=description,
            evidence_raw=evidence,
            remediation=(
                f"Restrict or remove access to '{path}'. "
                "Ensure sensitive files and directories are not served by the web server. "
                "For directory listings: set 'Options -Indexes' in Apache or "
                "'autoindex off;' in nginx. "
                "Remove .git, .env, and backup files from web-accessible directories."
            ),
        ))

    return findings
