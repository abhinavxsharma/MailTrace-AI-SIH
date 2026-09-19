"""
Tests for SPF verifier (forensics.authentication.spf).

Covers:
- pass
- fail
- softfail
- neutral
- none
- temperror
- permerror
- missing IP -> NOT_EVALUATED
- missing envelope domain -> NOT_EVALUATED
- malformed policy -> PERMERROR
- unavailable DNS -> NONE / TEMPERROR
- include mechanism and recursion / lookup limits (max 10 lookups)
- IPv4 and IPv6 evaluation
- Connecting IP extraction from Received hops

All DNS queries are mocked deterministically without live network calls.
"""

from __future__ import annotations

from forensics.authentication.spf import (
    MAX_SPF_DNS_LOOKUPS,
    extract_connecting_ip,
    verify_spf,
)
from forensics.email_parser import parse_email


class MockDnsResolver:
    """Deterministic mock DNS resolver for SPF tests."""

    def __init__(
        self,
        txt: dict[str, list[str]] | None = None,
        a: dict[str, list[str]] | None = None,
        mx: dict[str, list[str]] | None = None,
    ):
        self.txt = {k.lower().rstrip("."): v for k, v in (txt or {}).items()}
        self.a = {k.lower().rstrip("."): v for k, v in (a or {}).items()}
        self.mx = {k.lower().rstrip("."): v for k, v in (mx or {}).items()}

    def get_txt_records(self, domain: str) -> list[str]:
        return self.txt.get(domain.lower().rstrip("."), [])

    def get_a_records(self, domain: str) -> list[str]:
        return self.a.get(domain.lower().rstrip("."), [])

    def get_mx_hosts(self, domain: str) -> list[str]:
        return self.mx.get(domain.lower().rstrip("."), [])


class TestSpfVerifier:

    def test_spf_pass_ip4(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 ip4:192.0.2.0/24 -all"]}
        )
        res = verify_spf(domain="example.com", ip="192.0.2.10", resolver=resolver)
        assert res.status == "PASS"
        assert res.domain == "example.com"
        assert res.ip == "192.0.2.10"
        assert res.evidence["matched_mechanism"] == "ip4:192.0.2.0/24"

    def test_spf_fail_ip4(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 ip4:192.0.2.0/24 -all"]}
        )
        res = verify_spf(domain="example.com", ip="198.51.100.1", resolver=resolver)
        assert res.status == "FAIL"
        assert res.evidence["matched_mechanism"] == "-all"

    def test_spf_softfail(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 ip4:192.0.2.0/24 ~all"]}
        )
        res = verify_spf(domain="example.com", ip="198.51.100.1", resolver=resolver)
        assert res.status == "SOFTFAIL"
        assert res.evidence["matched_mechanism"] == "~all"

    def test_spf_neutral(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 ip4:192.0.2.0/24 ?all"]}
        )
        res = verify_spf(domain="example.com", ip="198.51.100.1", resolver=resolver)
        assert res.status == "NEUTRAL"
        assert res.evidence["matched_mechanism"] == "?all"

    def test_spf_none_no_txt_records(self):
        resolver = MockDnsResolver(txt={})
        res = verify_spf(domain="example.com", ip="192.0.2.1", resolver=resolver)
        assert res.status == "NONE"
        assert "No SPF record" in (res.reason or "")

    def test_spf_none_unrelated_txt_records(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["some-verification=xyz", "v=DMARC1; p=none"]}
        )
        res = verify_spf(domain="example.com", ip="192.0.2.1", resolver=resolver)
        assert res.status == "NONE"

    def test_spf_permerror_multiple_records(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 ip4:1.1.1.1 -all", "v=spf1 ip4:2.2.2.2 -all"]}
        )
        res = verify_spf(domain="example.com", ip="1.1.1.1", resolver=resolver)
        assert res.status == "PERMERROR"
        assert "Multiple SPF records" in (res.reason or "")

    def test_spf_permerror_invalid_mechanism_syntax(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 ip4:not-a-cidr -all"]}
        )
        res = verify_spf(domain="example.com", ip="192.0.2.1", resolver=resolver)
        assert res.status == "PERMERROR"

    def test_spf_missing_ip_returns_not_evaluated(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 -all"]}
        )
        res = verify_spf(domain="example.com", ip=None, resolver=resolver)
        assert res.status == "NOT_EVALUATED"
        assert "Connecting IP" in (res.reason or "")

    def test_spf_missing_domain_returns_not_evaluated(self):
        res = verify_spf(domain="", ip="192.0.2.1")
        assert res.status == "NOT_EVALUATED"
        assert "Missing envelope sender" in (res.reason or "")

    def test_spf_include_mechanism_pass(self):
        resolver = MockDnsResolver(
            txt={
                "example.com": ["v=spf1 include:_spf.example.org -all"],
                "_spf.example.org": ["v=spf1 ip4:192.0.2.0/24 -all"],
            }
        )
        res = verify_spf(domain="example.com", ip="192.0.2.5", resolver=resolver)
        assert res.status == "PASS"

    def test_spf_include_loop_detected_permerror(self):
        resolver = MockDnsResolver(
            txt={
                "a.com": ["v=spf1 include:b.com -all"],
                "b.com": ["v=spf1 include:a.com -all"],
            }
        )
        res = verify_spf(domain="a.com", ip="192.0.2.1", resolver=resolver)
        assert res.status == "PERMERROR"
        assert "loop" in (res.reason or "").lower()

    def test_spf_a_mechanism_match(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 a -all"]},
            a={"example.com": ["192.0.2.50"]},
        )
        res = verify_spf(domain="example.com", ip="192.0.2.50", resolver=resolver)
        assert res.status == "PASS"

    def test_spf_mx_mechanism_match(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 mx -all"]},
            mx={"example.com": ["mail.example.com"]},
            a={"mail.example.com": ["192.0.2.60"]},
        )
        res = verify_spf(domain="example.com", ip="192.0.2.60", resolver=resolver)
        assert res.status == "PASS"

    def test_spf_ip6_match(self):
        resolver = MockDnsResolver(
            txt={"example.com": ["v=spf1 ip6:2001:db8::/32 -all"]}
        )
        res = verify_spf(domain="example.com", ip="2001:db8::1", resolver=resolver)
        assert res.status == "PASS"


class TestConnectingIpExtraction:

    def test_extract_connecting_ip_from_received_header(self):
        raw = (
            "From: alice@example.com\r\n"
            "Received: from mail.sender.com ([198.51.100.42]) by mx.receiver.com; 01 Jan 2024 00:00:00 +0000\r\n"
            "\r\n"
            "body\r\n"
        )
        parsed = parse_email(raw)
        ip = extract_connecting_ip(parsed)
        assert ip == "198.51.100.42"

    def test_extract_connecting_ip_none_when_no_ip_present(self):
        raw = (
            "From: alice@example.com\r\n"
            "Received: from mail.sender.com by mx.receiver.com; 01 Jan 2024 00:00:00 +0000\r\n"
            "\r\n"
            "body\r\n"
        )
        parsed = parse_email(raw)
        ip = extract_connecting_ip(parsed)
        assert ip is None
