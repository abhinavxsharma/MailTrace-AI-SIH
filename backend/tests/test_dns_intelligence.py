"""
MAILTRACE AI — Unit tests for DNS intelligence resolution.

Tests verify:
- A, AAAA, MX, NS, TXT, CNAME record resolutions
- NXDOMAIN handling
- Timeout handling
- SERVFAIL handling
- Malformed domain handling
- No records handling
- TTL caching behavior
- Complete offline execution via mock queries
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from intelligence.cache import InMemoryTtlCache
from intelligence.dns.models import DnsIntelligenceResult, DnsRecordResult
from intelligence.dns.resolver import DnsIntelligenceResolver


def test_dns_record_result_model_immutability():
    """Verify DnsRecordResult is frozen."""
    rec = DnsRecordResult(
        domain="example.com",
        record_type="A",
        values=["93.184.216.34"],
        status="NOERROR",
    )
    assert rec.domain == "example.com"
    assert rec.record_type == "A"
    assert rec.values == ["93.184.216.34"]
    assert rec.status == "NOERROR"

    with pytest.raises(Exception):
        rec.values = ["1.1.1.1"]  # type: ignore


def test_dns_resolve_a_record_mock():
    """Verify resolving an A record via mock query function."""
    def mock_query(domain: str, rtype: str) -> list[str]:
        if domain == "example.com" and rtype == "A":
            return ["93.184.216.34"]
        return []

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    result = resolver.resolve_record("example.com", "A")

    assert result.domain == "example.com"
    assert result.record_type == "A"
    assert result.status == "NOERROR"
    assert result.values == ["93.184.216.34"]
    assert result.error is None


def test_dns_resolve_aaaa_record_mock():
    """Verify resolving an AAAA record via mock query function."""
    def mock_query(domain: str, rtype: str) -> list[str]:
        if domain == "example.com" and rtype == "AAAA":
            return ["2606:2800:220:1:248:1893:25c8:1946"]
        return []

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    result = resolver.resolve_record("example.com", "AAAA")

    assert result.status == "NOERROR"
    assert result.values == ["2606:2800:220:1:248:1893:25c8:1946"]


def test_dns_resolve_mx_record_mock():
    """Verify resolving MX records."""
    def mock_query(domain: str, rtype: str) -> list[str]:
        if domain == "example.com" and rtype == "MX":
            return ["10 mail.example.com.", "20 backup.example.com."]
        return []

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    result = resolver.resolve_record("example.com", "MX")

    assert result.status == "NOERROR"
    assert len(result.values) == 2
    assert "10 mail.example.com." in result.values


def test_dns_resolve_txt_record_mock():
    """Verify resolving TXT records (e.g. SPF/DMARC/verification)."""
    def mock_query(domain: str, rtype: str) -> list[str]:
        if domain == "example.com" and rtype == "TXT":
            return ['"v=spf1 -all"', '"google-site-verification=abc"']
        return []

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    result = resolver.resolve_record("example.com", "TXT")

    assert result.status == "NOERROR"
    assert len(result.values) == 2
    assert '"v=spf1 -all"' in result.values


def test_dns_resolve_cname_record_mock():
    """Verify resolving CNAME records."""
    def mock_query(domain: str, rtype: str) -> list[str]:
        if domain == "alias.example.com" and rtype == "CNAME":
            return ["target.example.com."]
        return []

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    result = resolver.resolve_record("alias.example.com", "CNAME")

    assert result.status == "NOERROR"
    assert result.values == ["target.example.com."]


def test_dns_resolve_nxdomain_mock():
    """Verify NXDOMAIN handling."""
    import dns.resolver

    def mock_query(domain: str, rtype: str) -> list[str]:
        raise dns.resolver.NXDOMAIN()

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    result = resolver.resolve_record("nonexistent.invalid", "A")

    assert result.status == "NXDOMAIN"
    assert result.values == []
    assert result.error is not None
    assert len(result.error) > 0


def test_dns_resolve_timeout_mock():
    """Verify timeout handling."""
    import dns.resolver

    def mock_query(domain: str, rtype: str) -> list[str]:
        raise dns.resolver.Timeout()

    resolver = DnsIntelligenceResolver(timeout=1.0, mock_query_func=mock_query)
    result = resolver.resolve_record("timeout.invalid", "A")

    assert result.status == "TIMEOUT"
    assert result.values == []
    assert result.error is not None
    assert len(result.error) > 0


def test_dns_resolve_servfail_mock():
    """Verify SERVFAIL handling."""
    import dns.resolver

    def mock_query(domain: str, rtype: str) -> list[str]:
        raise dns.resolver.NoNameservers()

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    result = resolver.resolve_record("servfail.invalid", "A")

    assert result.status == "SERVFAIL"
    assert result.values == []


def test_dns_resolve_no_records_mock():
    """Verify empty/NoAnswer handling."""
    import dns.resolver

    def mock_query(domain: str, rtype: str) -> list[str]:
        raise dns.resolver.NoAnswer()

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    result = resolver.resolve_record("example.com", "AAAA")

    assert result.status == "NO_RECORDS"
    assert result.values == []


def test_dns_resolve_malformed_domain():
    """Verify malformed domain rejection without attempting query."""
    resolver = DnsIntelligenceResolver()

    # Empty domain
    res1 = resolver.resolve_record("", "A")
    assert res1.status == "MALFORMED"
    assert "malformed" in str(res1.error).lower()

    # Domain with spaces or illegal characters
    res2 = resolver.resolve_record("invalid domain!@#.com", "A")
    assert res2.status == "MALFORMED"

    # Unsupported record type
    res3 = resolver.resolve_record("example.com", "UNSUPPORTED_TYPE")
    assert res3.status == "MALFORMED"


def test_dns_caching_behavior():
    """Verify that resolution results are cached and retrieved."""
    call_count = 0

    def mock_query(domain: str, rtype: str) -> list[str]:
        nonlocal call_count
        call_count += 1
        return ["1.2.3.4"]

    cache = InMemoryTtlCache[DnsRecordResult](ttl_seconds=300)
    resolver = DnsIntelligenceResolver(cache=cache, mock_query_func=mock_query)

    res1 = resolver.resolve_record("cached.example.com", "A")
    assert res1.status == "NOERROR"
    assert call_count == 1

    # Second lookup should hit cache
    res2 = resolver.resolve_record("cached.example.com", "A")
    assert res2.status == "NOERROR"
    assert res2.values == ["1.2.3.4"]
    assert call_count == 1


def test_dns_resolve_domain_all_records():
    """Verify comprehensive domain resolution across standard record types."""
    def mock_query(domain: str, rtype: str) -> list[str]:
        if rtype == "A":
            return ["93.184.216.34"]
        elif rtype == "MX":
            return ["10 mail.example.com."]
        elif rtype == "TXT":
            return ['"v=spf1 -all"']
        elif rtype == "NS":
            return ["ns1.example.com.", "ns2.example.com."]
        return []

    resolver = DnsIntelligenceResolver(mock_query_func=mock_query)
    full_result = resolver.resolve_domain("example.com")

    assert isinstance(full_result, DnsIntelligenceResult)
    assert full_result.domain == "example.com"
    assert full_result.a_records == ["93.184.216.34"]
    assert full_result.mx_records == ["10 mail.example.com."]
    assert full_result.txt_records == ['"v=spf1 -all"']
    assert len(full_result.ns_records) == 2
    assert full_result.status == "NOERROR"
