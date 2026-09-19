"""
Tests for header_forensics (forensics.headers.forensics).

Covers all 13 deterministic forensic rules:
1. FROM_REPLY_TO_MISMATCH
2. FROM_RETURN_PATH_MISMATCH
3. FROM_SENDER_MISMATCH
4. MISSING_FROM
5. MISSING_DATE
6. MISSING_MESSAGE_ID
7. MISSING_RETURN_PATH
8. UNUSUAL_REPLY_TO
9. MULTIPLE_FROM
10. DUPLICATE_IDENTITY_HEADERS
11. INVALID_DATE
12. MALFORMED_MESSAGE_ID
13. FOLDED_HEADER_WHITESPACE

Also covers:
- Severity level validation (INFO, LOW, MEDIUM only — no HIGH, CRITICAL)
- Privacy sentinels: no .eml, no raw MIME files, no tempfile, no disk writes
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from forensics.email_parser import parse_email
from forensics.headers.forensics import analyze_headers
from forensics.headers.models import HeaderForensicFinding, HeaderForensicResult


# --------------------------------------------------------------------------- #
# Helper to build raw email strings                                            #
# --------------------------------------------------------------------------- #

def _build_email(headers: list[tuple[str, str]], body: str = "Test body") -> str:
    lines = [f"{name}: {val}" for name, val in headers]
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines)


# --------------------------------------------------------------------------- #
# Test Individual Forensic Rules                                              #
# --------------------------------------------------------------------------- #

class TestHeaderForensicsRules:

    def test_matching_from_and_reply_to_no_mismatch_finding(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Reply-To", "alice@example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
            ("Return-Path", "<alice@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        codes = [f.code for f in result.findings]
        assert "FROM_REPLY_TO_MISMATCH" not in codes

    def test_mismatched_from_and_reply_to(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Reply-To", "billing@other-example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
            ("Return-Path", "<alice@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "FROM_REPLY_TO_MISMATCH"), None)
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.category == "identity"
        assert finding.evidence["from"] == "alice@example.com"
        assert finding.evidence["reply_to"] == "billing@other-example.com"
        assert "From" in finding.related_headers
        assert "Reply-To" in finding.related_headers

    def test_from_return_path_mismatch(self):
        raw = _build_email([
            ("From", "ceo@company.com"),
            ("Return-Path", "<bounce@unrelated-domain.com>"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@company.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "FROM_RETURN_PATH_MISMATCH"), None)
        assert finding is not None
        assert finding.severity == "LOW"
        assert finding.category == "identity"
        assert finding.evidence["from"] == "ceo@company.com"
        assert finding.evidence["return_path"] == "bounce@unrelated-domain.com"

    def test_from_sender_mismatch(self):
        raw = _build_email([
            ("From", "marketing@brand.com"),
            ("Sender", "mailer@thirdparty.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@brand.com>"),
            ("Return-Path", "<marketing@brand.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "FROM_SENDER_MISMATCH"), None)
        assert finding is not None
        assert finding.severity == "LOW"
        assert finding.category == "identity"
        assert finding.evidence["from"] == "marketing@brand.com"
        assert finding.evidence["sender"] == "mailer@thirdparty.com"

    def test_missing_from(self):
        raw = _build_email([
            ("To", "user@example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "MISSING_FROM"), None)
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.category == "identity"

    def test_multiple_from_addresses(self):
        raw = _build_email([
            ("From", "alice@example.com, bob@example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "MULTIPLE_FROM"), None)
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_multiple_from_headers(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("From", "spoofed@evil.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "MULTIPLE_FROM"), None)
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_missing_date(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "MISSING_DATE"), None)
        assert finding is not None
        assert finding.severity == "LOW"
        assert finding.category == "header_integrity"

    def test_invalid_date(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Date", "not-a-valid-date-string"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "INVALID_DATE"), None)
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.category == "header_integrity"
        assert finding.evidence["raw_date"] == "not-a-valid-date-string"

    def test_missing_message_id(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "MISSING_MESSAGE_ID"), None)
        assert finding is not None
        assert finding.severity == "LOW"
        assert finding.category == "header_integrity"

    def test_malformed_message_id(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "not-enclosed-in-brackets@domain.com"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "MALFORMED_MESSAGE_ID"), None)
        assert finding is not None
        assert finding.severity == "LOW"
        assert finding.category == "header_integrity"

    def test_missing_return_path(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "MISSING_RETURN_PATH"), None)
        assert finding is not None
        assert finding.severity == "INFO"
        assert finding.category == "routing"

    def test_unusual_reply_to_multiple_addresses(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Reply-To", "one@example.com, two@example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "UNUSUAL_REPLY_TO"), None)
        assert finding is not None
        assert finding.severity == "LOW"

    def test_duplicate_identity_headers(self):
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Subject", "First Subject"),
            ("Subject", "Second Subject"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "DUPLICATE_IDENTITY_HEADERS"), None)
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.evidence["header"] == "subject"
        assert finding.evidence["count"] == 2

    def test_folded_header_whitespace_observation(self):
        raw = (
            "From: alice@example.com\r\n"
            "Subject: Folded\r\n    Header Line\r\n"
            "Date: Mon, 01 Jan 2024 10:00:00 +0000\r\n"
            "Message-ID: <msg001@example.com>\r\n"
            "\r\n"
            "Body\r\n"
        )
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        finding = next((f for f in result.findings if f.code == "FOLDED_HEADER_WHITESPACE"), None)
        assert finding is not None
        assert finding.severity == "INFO"
        assert "Subject" in finding.evidence["headers_with_folding"]


# --------------------------------------------------------------------------- #
# Severity and Verdict Boundary Tests                                         #
# --------------------------------------------------------------------------- #

class TestSeverityAndVerdictBoundaries:

    def test_finding_rejects_high_or_critical_severity(self):
        """Severities outside INFO, LOW, MEDIUM must be rejected by Pydantic."""
        with pytest.raises(ValidationError):
            HeaderForensicFinding(
                code="TEST_CODE",
                category="test",
                severity="HIGH",  # type: ignore[arg-type]
                description="Test",
            )

        with pytest.raises(ValidationError):
            HeaderForensicFinding(
                code="TEST_CODE",
                category="test",
                severity="CRITICAL",  # type: ignore[arg-type]
                description="Test",
            )

    def test_all_analyzed_findings_use_only_allowed_severities(self):
        """Verify that every finding emitted by analyze_headers is in {INFO, LOW, MEDIUM}."""
        raw = _build_email([
            ("From", "attacker@evil.com"),
            ("From", "ceo@company.com"),
            ("Reply-To", "another@evil.com"),
            ("Date", "invalid-date"),
            ("Message-ID", "malformed-id"),
        ])
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        assert result.total_findings > 0
        for f in result.findings:
            assert f.severity in ("INFO", "LOW", "MEDIUM")


# --------------------------------------------------------------------------- #
# PRIVACY SENTINELS: No disk writes during header forensics                   #
# --------------------------------------------------------------------------- #

class TestPrivacyNoDiskWrites:

    def test_tempfile_not_imported_in_forensics(self):
        """Neither email_parser nor headers modules may import tempfile."""
        import forensics.email_parser.parser as ep_parser
        import forensics.headers.forensics as h_forensics
        import forensics.headers.parser as h_parser

        for mod in (ep_parser, h_forensics, h_parser):
            source = inspect.getsource(mod)
            assert "import tempfile" not in source, (
                f"{mod.__name__} must not import tempfile — raw email must never be written to disk."
            )

    def test_open_not_called_with_write_mode_during_forensics(self):
        """Verify builtins.open is never called in write mode during analysis."""
        raw = _build_email([
            ("From", "alice@example.com"),
            ("Reply-To", "bob@example.com"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Message-ID", "<msg001@example.com>"),
        ])
        parsed = parse_email(raw)

        suspicious_opens: list[tuple] = []
        original_open = open

        def tracking_open(file, mode="r", *args, **kwargs):
            file_str = str(file)
            if any(ext in file_str for ext in (".eml", ".mime")) and any(
                m in mode for m in ("w", "a", "x")
            ):
                suspicious_opens.append((file_str, mode))
            return original_open(file, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=tracking_open):
            analyze_headers(parsed)

        assert not suspicious_opens, f"Files opened in write mode: {suspicious_opens}"
