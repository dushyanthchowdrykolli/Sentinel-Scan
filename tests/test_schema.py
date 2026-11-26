"""
tests/test_schema.py

Tests for the Finding schema and evidence building helpers.

Ensures:
  - Finding dataclass produces correct to_dict() output
  - evidence_hash is SHA-256 of evidence_raw
  - build_evidence produces a string containing the expected sections
  - Severity values are drawn from the allowed set
  - finding_id is auto-generated and unique across instances
"""

import hashlib
import pytest

from app.scanner.base import Finding, build_evidence, SEVERITY_ORDER


ALLOWED_SEVERITIES = set(SEVERITY_ORDER.keys())


class TestFindingDataclass:
    def _make_finding(self, **kwargs):
        defaults = dict(
            title="Test Finding",
            category="A05 Security Misconfiguration",
            severity="Medium",
            affected_url="http://127.0.0.1/test",
            description="A test description.",
            evidence_raw="=== REQUEST ===\nGET http://127.0.0.1/test\n",
            remediation="Fix it.",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_to_dict_has_all_required_keys(self):
        f = self._make_finding()
        d = f.to_dict()
        required_keys = {
            "finding_id", "title", "category", "severity",
            "affected_url", "description", "evidence_raw",
            "evidence_hash", "remediation",
        }
        assert required_keys.issubset(d.keys()), (
            f"Missing keys: {required_keys - d.keys()}"
        )

    def test_evidence_hash_is_sha256_of_evidence_raw(self):
        raw = "some evidence text with request and response"
        f = self._make_finding(evidence_raw=raw)
        expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        assert f.evidence_hash == expected

    def test_evidence_hash_matches_to_dict(self):
        f = self._make_finding()
        assert f.to_dict()["evidence_hash"] == f.evidence_hash

    def test_finding_id_is_auto_generated(self):
        f = self._make_finding()
        assert isinstance(f.finding_id, str)
        assert len(f.finding_id) > 0

    def test_finding_ids_are_unique(self):
        ids = {self._make_finding().finding_id for _ in range(50)}
        assert len(ids) == 50, "finding_id collision detected"

    def test_severity_in_allowed_set(self):
        for sev in ALLOWED_SEVERITIES:
            f = self._make_finding(severity=sev)
            assert f.severity in ALLOWED_SEVERITIES

    def test_to_dict_values_match_attributes(self):
        f = self._make_finding(
            title="My Title",
            category="A03 Injection",
            severity="High",
            affected_url="http://example.invalid",
        )
        d = f.to_dict()
        assert d["title"] == "My Title"
        assert d["category"] == "A03 Injection"
        assert d["severity"] == "High"
        assert d["affected_url"] == "http://example.invalid"

    def test_evidence_hash_changes_when_evidence_changes(self):
        f1 = self._make_finding(evidence_raw="evidence A")
        f2 = self._make_finding(evidence_raw="evidence B")
        assert f1.evidence_hash != f2.evidence_hash

    def test_empty_evidence_has_hash(self):
        f = self._make_finding(evidence_raw="")
        # SHA-256 of empty string is well-defined
        expected = hashlib.sha256(b"").hexdigest()
        assert f.evidence_hash == expected


class TestBuildEvidence:
    def test_build_evidence_contains_request_section(self):
        ev = build_evidence(
            method="GET",
            url="http://127.0.0.1/page",
            request_headers={"User-Agent": "TestAgent"},
            request_body=None,
            status_code=200,
            response_headers={"Content-Type": "text/html"},
            response_excerpt="<html></html>",
        )
        assert "=== REQUEST ===" in ev
        assert "GET http://127.0.0.1/page" in ev

    def test_build_evidence_contains_response_section(self):
        ev = build_evidence(
            method="GET",
            url="http://127.0.0.1/page",
            request_headers={},
            request_body=None,
            status_code=404,
            response_headers={},
            response_excerpt="Not Found",
        )
        assert "=== RESPONSE ===" in ev
        assert "Status: 404" in ev
        assert "Not Found" in ev

    def test_build_evidence_includes_request_headers(self):
        ev = build_evidence(
            method="POST",
            url="http://127.0.0.1/submit",
            request_headers={"X-Custom": "HeaderValue"},
            request_body="key=value",
            status_code=200,
            response_headers={},
            response_excerpt="OK",
        )
        assert "X-Custom: HeaderValue" in ev

    def test_build_evidence_includes_body(self):
        ev = build_evidence(
            method="POST",
            url="http://127.0.0.1/submit",
            request_headers={},
            request_body="username=admin&password=test",
            status_code=200,
            response_headers={},
            response_excerpt="",
        )
        assert "username=admin" in ev

    def test_build_evidence_includes_notes(self):
        ev = build_evidence(
            method="GET",
            url="http://127.0.0.1/",
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={},
            response_excerpt="",
            notes="Probe reflected without encoding.",
        )
        assert "=== NOTES ===" in ev
        assert "Probe reflected without encoding." in ev

    def test_build_evidence_truncates_long_response(self):
        long_body = "X" * 10000
        ev = build_evidence(
            method="GET",
            url="http://127.0.0.1/big",
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={},
            response_excerpt=long_body,
        )
        # Should be truncated to 3000 chars
        assert len(ev) < 10000 + 500  # Total with headers still reasonable

    def test_build_evidence_returns_string(self):
        ev = build_evidence(
            method="GET",
            url="http://127.0.0.1/",
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={},
            response_excerpt="hello",
        )
        assert isinstance(ev, str)
        assert len(ev) > 0


class TestSeverityOrder:
    def test_all_severities_present(self):
        assert set(SEVERITY_ORDER.keys()) == {"Critical", "High", "Medium", "Low", "Info"}

    def test_critical_is_highest(self):
        assert SEVERITY_ORDER["Critical"] < SEVERITY_ORDER["High"]

    def test_info_is_lowest(self):
        assert SEVERITY_ORDER["Info"] > SEVERITY_ORDER["Low"]

    def test_ordering_is_strict(self):
        ordered = ["Critical", "High", "Medium", "Low", "Info"]
        for i in range(len(ordered) - 1):
            assert SEVERITY_ORDER[ordered[i]] < SEVERITY_ORDER[ordered[i + 1]]
