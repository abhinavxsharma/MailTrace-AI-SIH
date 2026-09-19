"""
Tests for DMARC evaluator (forensics.authentication.dmarc).

Covers:
- DMARC pass via SPF alignment
- DMARC pass via DKIM alignment
- DMARC failure when neither is aligned
- Policy enforcement: none, quarantine, reject
- Subdomain fallback to organizational domain policy
- Missing DMARC policy record -> NONE
- Malformed DMARC policy records (multiple records, bad p=) -> PERMERROR

All tests operate strictly in memory with zero network calls.
"""

from __future__ import annotations

from forensics.authentication.dmarc import evaluate_dmarc, parse_dmarc_tags
from forensics.authentication.models import (
    AlignmentResult,
    DkimResult,
    DkimSignatureResult,
    DmarcResult,
    SpfResult,
)
from forensics.email_parser import parse_email


class MockDmarcResolver:
    """Mock DNS resolver returning configured DMARC records."""

    def __init__(self, records: dict[str, list[str]] | None = None):
        self.records = {k.lower().rstrip("."): v for k, v in (records or {}).items()}

    def get_txt_records(self, domain: str) -> list[str]:
        return self.records.get(domain.lower().rstrip("."), [])

    def get_a_records(self, domain: str) -> list[str]:
        return []

    def get_mx_hosts(self, domain: str) -> list[str]:
        return []


def _make_email(from_addr: str = "alice@example.com", return_path: str = "alice@example.com"):
    raw = (
        f"From: {from_addr}\r\n"
        f"Return-Path: <{return_path}>\r\n"
        "Subject: DMARC Test\r\n"
        "\r\n"
        "Body\r\n"
    )
    return parse_email(raw)


class TestDmarcEvaluator:

    def test_dmarc_pass_via_spf_alignment(self):
        email = _make_email(from_addr="alice@example.com", return_path="bounce@example.com")
        spf_res = SpfResult(domain="example.com", ip="1.2.3.4", status="PASS")
        dkim_res = DkimResult(status="missing", signatures=[])

        resolver = MockDmarcResolver(
            records={"_dmarc.example.com": ["v=DMARC1; p=reject; aspf=r;"]}
        )

        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert isinstance(res, DmarcResult)
        assert res.status == "PASS"
        assert res.disposition == "none"
        assert res.spf_aligned is True
        assert res.dkim_aligned is False

    def test_dmarc_pass_via_dkim_alignment(self):
        email = _make_email(from_addr="alice@example.com", return_path="unrelated@other.com")
        spf_res = SpfResult(domain="other.com", ip="1.2.3.4", status="PASS")
        dkim_res = DkimResult(
            status="valid",
            signatures=[
                DkimSignatureResult(
                    domain="example.com",
                    selector="s1",
                    result="valid",
                    signature_valid=True,
                )
            ],
        )

        resolver = MockDmarcResolver(
            records={"_dmarc.example.com": ["v=DMARC1; p=reject; adkim=r;"]}
        )

        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert res.status == "PASS"
        assert res.disposition == "none"
        assert res.spf_aligned is False
        assert res.dkim_aligned is True

    def test_dmarc_fail_neither_aligned_policy_reject(self):
        email = _make_email(from_addr="alice@example.com", return_path="bounce@other.com")
        spf_res = SpfResult(domain="other.com", ip="1.2.3.4", status="PASS")
        dkim_res = DkimResult(
            status="valid",
            signatures=[
                DkimSignatureResult(
                    domain="thirdparty.com",
                    selector="s1",
                    result="valid",
                    signature_valid=True,
                )
            ],
        )

        resolver = MockDmarcResolver(
            records={"_dmarc.example.com": ["v=DMARC1; p=reject;"]}
        )

        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert res.status == "FAIL"
        assert res.policy == "reject"
        assert res.disposition == "reject"
        assert res.spf_aligned is False
        assert res.dkim_aligned is False

    def test_dmarc_fail_policy_quarantine(self):
        email = _make_email(from_addr="alice@example.com", return_path="bounce@other.com")
        spf_res = SpfResult(domain="other.com", ip="1.2.3.4", status="PASS")
        dkim_res = DkimResult(status="missing", signatures=[])

        resolver = MockDmarcResolver(
            records={"_dmarc.example.com": ["v=DMARC1; p=quarantine;"]}
        )

        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert res.status == "FAIL"
        assert res.policy == "quarantine"
        assert res.disposition == "quarantine"

    def test_dmarc_fail_policy_none(self):
        email = _make_email(from_addr="alice@example.com", return_path="bounce@other.com")
        spf_res = SpfResult(domain="other.com", ip="1.2.3.4", status="PASS")
        dkim_res = DkimResult(status="missing", signatures=[])

        resolver = MockDmarcResolver(
            records={"_dmarc.example.com": ["v=DMARC1; p=none;"]}
        )

        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert res.status == "FAIL"
        assert res.policy == "none"
        assert res.disposition == "none"

    def test_dmarc_subdomain_fallback_to_org_domain(self):
        # From mail.example.com, no DMARC on mail.example.com, but exists on example.com
        email = _make_email(from_addr="alice@mail.example.com", return_path="bounce@mail.example.com")
        spf_res = SpfResult(domain="mail.example.com", ip="1.2.3.4", status="PASS")
        dkim_res = DkimResult(status="missing", signatures=[])

        resolver = MockDmarcResolver(
            records={"_dmarc.example.com": ["v=DMARC1; p=quarantine; sp=reject;"]}
        )

        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert res.policy_domain == "example.com"
        assert res.status == "PASS"  # Relaxed SPF aligns mail.example.com with example.com

    def test_dmarc_missing_policy_returns_none(self):
        email = _make_email(from_addr="alice@example.com")
        spf_res = SpfResult(domain="example.com", status="PASS")
        dkim_res = DkimResult(status="missing", signatures=[])

        resolver = MockDmarcResolver(records={})
        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert res.status == "NONE"
        assert res.policy == "none_found"
        assert res.disposition == "none"

    def test_dmarc_permerror_multiple_records(self):
        email = _make_email(from_addr="alice@example.com")
        spf_res = SpfResult(domain="example.com", status="PASS")
        dkim_res = DkimResult(status="missing", signatures=[])

        resolver = MockDmarcResolver(
            records={
                "_dmarc.example.com": ["v=DMARC1; p=reject;", "v=DMARC1; p=quarantine;"]
            }
        )
        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert res.status == "PERMERROR"
        assert "Multiple DMARC records" in (res.error or "")

    def test_dmarc_permerror_invalid_policy_tag(self):
        email = _make_email(from_addr="alice@example.com")
        spf_res = SpfResult(domain="example.com", status="PASS")
        dkim_res = DkimResult(status="missing", signatures=[])

        resolver = MockDmarcResolver(
            records={"_dmarc.example.com": ["v=DMARC1; p=destroy;"]}
        )
        res = evaluate_dmarc(email, spf_res, dkim_res, resolver=resolver)

        assert res.status == "PERMERROR"
        assert "Invalid p=" in (res.error or "")

    def test_parse_dmarc_tags_helper(self):
        rec = "v=DMARC1; p=reject; sp=quarantine; aspf=s; adkim=r; pct=50;"
        tags = parse_dmarc_tags(rec)
        assert tags["v"] == "DMARC1"
        assert tags["p"] == "reject"
        assert tags["sp"] == "quarantine"
        assert tags["aspf"] == "s"
        assert tags["adkim"] == "r"
        assert tags["pct"] == "50"
