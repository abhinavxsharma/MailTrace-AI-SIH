"""
Tests for full email authentication verification pipeline (forensics.authentication).

Covers:
- verify_authentication end-to-end orchestration
- Domain alignment: exact, relaxed subdomain, misalignment
- Authentication-Results header comparison and discrepancy detection
- Privacy sentinels: no disk writes, no tempfile imports, no .eml/.mime creation
"""

from __future__ import annotations

import inspect
from unittest.mock import patch

import pytest

from forensics.authentication import (
    AuthenticationDiscrepancy,
    AuthenticationResult,
    check_dkim_alignment,
    check_spf_alignment,
    evaluate_alignment,
    get_organizational_domain,
    parse_authentication_results_header,
    verify_authentication,
)
from forensics.authentication.spf import DnsResolverProtocol
from forensics.email_parser import parse_email


class MockCombinedResolver:
    """Mock DNS resolver for end-to-end authentication tests."""

    def __init__(self, txt: dict[str, list[str]] | None = None):
        self.txt = {k.lower().rstrip("."): v for k, v in (txt or {}).items()}

    def get_txt_records(self, domain: str) -> list[str]:
        return self.txt.get(domain.lower().rstrip("."), [])

    def get_a_records(self, domain: str) -> list[str]:
        return []

    def get_mx_hosts(self, domain: str) -> list[str]:
        return []


# --------------------------------------------------------------------------- #
# Domain Alignment Tests                                                      #
# --------------------------------------------------------------------------- #

class TestAlignment:

    def test_get_organizational_domain(self):
        assert get_organizational_domain("example.com") == "example.com"
        assert get_organizational_domain("mail.example.com") == "example.com"
        assert get_organizational_domain("sub.mail.example.com") == "example.com"
        assert get_organizational_domain("mail.example.co.uk") == "example.co.uk"
        assert get_organizational_domain("corp.bank.gov.in") == "bank.gov.in"
        assert get_organizational_domain("localhost") == "localhost"

    def test_spf_alignment_relaxed(self):
        # Subdomains of the same org domain align in relaxed mode
        assert check_spf_alignment("example.com", "mail.example.com", mode="relaxed") is True
        assert check_spf_alignment("news.example.com", "bounces.example.com", mode="relaxed") is True
        assert check_spf_alignment("example.com", "other.com", mode="relaxed") is False

    def test_spf_alignment_strict(self):
        # Strict mode requires exact FQDN match
        assert check_spf_alignment("example.com", "example.com", mode="strict") is True
        assert check_spf_alignment("example.com", "mail.example.com", mode="strict") is False

    def test_dkim_alignment_relaxed(self):
        assert check_dkim_alignment("example.com", "mail.example.com", mode="relaxed") is True
        assert check_dkim_alignment("example.com", "unrelated.org", mode="relaxed") is False

    def test_dkim_alignment_strict(self):
        assert check_dkim_alignment("example.com", "example.com", mode="strict") is True
        assert check_dkim_alignment("example.com", "mail.example.com", mode="strict") is False

    def test_evaluate_alignment_helper(self):
        res = evaluate_alignment(
            from_domain="example.com",
            return_path_domain="mail.example.com",
            dkim_domains=["mail.example.com", "other.com"],
            aspf="r",
            adkim="r",
        )
        assert res.spf_aligned is True
        assert res.dkim_aligned is True
        assert res.spf_mode == "relaxed"
        assert res.dkim_mode == "relaxed"


# --------------------------------------------------------------------------- #
# Authentication-Results Header Comparison Tests                              #
# --------------------------------------------------------------------------- #

class TestAuthenticationResultsComparison:

    def test_parse_authentication_results_header(self):
        header = (
            "mx.google.com; dkim=pass header.i=@example.com; "
            "spf=pass (google.com: domain designates 1.2.3.4); "
            "dmarc=pass (p=REJECT)"
        )
        claims = parse_authentication_results_header(header)
        assert claims.get("dkim") == "pass"
        assert claims.get("spf") == "pass"
        assert claims.get("dmarc") == "pass"

    def test_discrepancy_claimed_pass_verified_fail(self):
        raw = (
            "From: alice@example.com\r\n"
            "Return-Path: <bounce@example.com>\r\n"
            "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"
            "Received: from [198.51.100.99] by mx.google.com; 01 Jan 2024 00:00:00 +0000\r\n"
            "\r\n"
            "body\r\n"
        )
        parsed = parse_email(raw)

        # SPF policy only permits 192.0.2.1; 198.51.100.99 will fail
        resolver = MockCombinedResolver(
            txt={
                "example.com": ["v=spf1 ip4:192.0.2.1 -all"],
                "_dmarc.example.com": ["v=DMARC1; p=reject;"],
            }
        )

        auth_res = verify_authentication(parsed, resolver=resolver)

        assert isinstance(auth_res, AuthenticationResult)
        assert auth_res.spf.status == "FAIL"

        # Discrepancy detected between claimed spf=pass and verified spf=FAIL
        spf_disc = next((d for d in auth_res.discrepancies if d.protocol == "spf"), None)
        assert spf_disc is not None
        assert spf_disc.header_claimed_result == "pass"
        assert spf_disc.locally_verified_result == "fail"

    def test_matching_results_no_discrepancies(self):
        raw = (
            "From: alice@example.com\r\n"
            "Return-Path: <bounce@example.com>\r\n"
            "Authentication-Results: mx.google.com; spf=pass; dmarc=pass\r\n"
            "Received: from [192.0.2.1] by mx.google.com; 01 Jan 2024 00:00:00 +0000\r\n"
            "\r\n"
            "body\r\n"
        )
        parsed = parse_email(raw)

        resolver = MockCombinedResolver(
            txt={
                "example.com": ["v=spf1 ip4:192.0.2.1 -all"],
                "_dmarc.example.com": ["v=DMARC1; p=none;"],
            }
        )

        auth_res = verify_authentication(parsed, resolver=resolver)
        assert auth_res.spf.status == "PASS"
        assert auth_res.dmarc.status == "PASS"

        # No SPF or DMARC discrepancies
        assert not any(d.protocol == "spf" for d in auth_res.discrepancies)
        assert not any(d.protocol == "dmarc" for d in auth_res.discrepancies)


# --------------------------------------------------------------------------- #
# PRIVACY SENTINELS: No disk writes during authentication verification        #
# --------------------------------------------------------------------------- #

class TestPrivacyNoDiskWrites:

    def test_tempfile_not_imported_in_authentication(self):
        """No module in forensics.authentication may import tempfile."""
        import forensics.authentication.alignment as al_mod
        import forensics.authentication.dkim as dkim_mod
        import forensics.authentication.dmarc as dmarc_mod
        import forensics.authentication.models as models_mod
        import forensics.authentication.spf as spf_mod
        import forensics.authentication.verifier as verifier_mod

        for mod in (al_mod, dkim_mod, dmarc_mod, models_mod, spf_mod, verifier_mod):
            source = inspect.getsource(mod)
            assert "import tempfile" not in source, (
                f"{mod.__name__} must not import tempfile — email data must remain in memory."
            )

    def test_open_not_called_in_write_mode_during_verification(self):
        """Verify builtins.open is never called in write mode during authentication."""
        raw = (
            "From: alice@example.com\r\n"
            "Return-Path: <bounce@example.com>\r\n"
            "Subject: Privacy Test\r\n"
            "\r\n"
            "body\r\n"
        )
        parsed = parse_email(raw)
        resolver = MockCombinedResolver(txt={})

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
            verify_authentication(parsed, resolver=resolver)

        assert not suspicious_opens, f"Files opened in write mode: {suspicious_opens}"
