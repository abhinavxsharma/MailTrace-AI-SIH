"""
MAILTRACE AI — Unit tests for Threat Reputation & Indicator Extraction.

Tests verify:
- Configured provider responses
- Provider unavailable handling
- Provider error handling
- Default behavior when no provider is configured (NOT_CONFIGURED)
- Dependency injection support
- Indicator extraction: domains, IPs, URLs, deduplication, and source provenance
- DnsblReputationProvider handling (clean/NXDOMAIN, listed/A record, timeout)
- Privacy enforcement: strictly in-memory, no .eml, no MIME to disk, no tempfile in intelligence
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from forensics.email_parser.models import (
    ExtractedUrl,
    ParsedAddress,
    ParsedEmail,
    ParsedHeader,
    ReceivedHop,
)
from intelligence.enricher import EmailIntelligenceEnricher
from intelligence.extractors import extract_indicators
from intelligence.reputation.models import (
    AggregatedReputationResult,
    ReputationResult,
)
from intelligence.reputation.providers import (
    DnsblReputationProvider,
    MockReputationProvider,
    NotConfiguredReputationProvider,
)
from intelligence.reputation.service import ReputationService


def test_reputation_models_immutability():
    """Verify reputation result models are frozen."""
    res = ReputationResult(
        indicator="evil.com",
        indicator_type="domain",
        provider="mock",
        score=0.9,
        category="phishing",
        confidence=0.85,
        raw_status="MALICIOUS",
    )
    assert res.indicator == "evil.com"
    assert res.score == 0.9

    with pytest.raises(Exception):
        res.score = 0.5  # type: ignore


def test_reputation_no_provider_configured():
    """Verify default behavior when no provider is configured is NOT_CONFIGURED."""
    service = ReputationService()  # Default: [NotConfiguredReputationProvider()]

    res = service.check("example.com", "domain")

    assert res.status == "NOT_CONFIGURED"
    assert len(res.results) == 1
    assert res.results[0].raw_status == "NOT_CONFIGURED"
    assert res.results[0].score is None
    assert "No reputation providers configured" in res.summary


def test_reputation_configured_mock_provider():
    """Verify reputation resolution with a configured mock provider."""
    mock_data = {
        "phishing.example": ReputationResult(
            indicator="phishing.example",
            indicator_type="domain",
            provider="mock_vendor",
            score=0.95,
            category="phishing",
            confidence=0.9,
            raw_status="MALICIOUS",
        ),
        "clean.example": ReputationResult(
            indicator="clean.example",
            indicator_type="domain",
            provider="mock_vendor",
            score=0.0,
            category="clean",
            confidence=0.95,
            raw_status="CLEAN",
        ),
    }

    provider = MockReputationProvider(name="mock_vendor", mock_data=mock_data)
    service = ReputationService(providers=[provider])

    bad_res = service.check("phishing.example", "domain")
    assert bad_res.status == "MALICIOUS"
    assert bad_res.results[0].score == 0.95
    assert "listed by: mock_vendor" in bad_res.summary

    clean_res = service.check("clean.example", "domain")
    assert clean_res.status == "CLEAN"
    assert clean_res.results[0].score == 0.0
    assert "No listings found" in clean_res.summary


def test_reputation_provider_unavailable():
    """Verify handling when a provider is marked not configured / unavailable."""
    provider = MockReputationProvider(name="disabled_vendor", configured=False)
    service = ReputationService(providers=[provider])

    res = service.check("example.com", "domain")
    assert res.status == "NOT_CONFIGURED"
    assert res.results[0].raw_status == "NOT_CONFIGURED"


def test_reputation_provider_error():
    """Verify handling when a provider raises an exception."""
    def broken_check(indicator: str, indicator_type: str) -> ReputationResult:
        raise ConnectionResetError("Remote reputation API unreachable")

    provider = MockReputationProvider(mock_func=broken_check)
    service = ReputationService(providers=[provider])

    res = service.check("example.com", "domain")
    assert res.status == "ERROR"
    assert res.results[0].raw_status == "ERROR"
    assert "ConnectionResetError" in str(res.results[0].evidence.get("error"))


def test_dnsbl_reputation_provider_clean_and_listed():
    """Verify DnsblReputationProvider with mock DNS query function."""
    def mock_dns(query_host: str, rtype: str) -> list[str]:
        if "1.0.0.127" in query_host:  # 127.0.0.1 reversed
            return ["127.0.0.2"]  # Listed in DNSBL
        import dns.resolver
        raise dns.resolver.NXDOMAIN()  # Not listed

    provider = DnsblReputationProvider(zone="zen.spamhaus.org", dns_query_func=mock_dns)

    # Listed IP
    res_listed = provider.check_indicator("127.0.0.1", "ip")
    assert res_listed.raw_status == "LISTED"
    assert res_listed.score == 1.0

    # Clean IP (NXDOMAIN)
    res_clean = provider.check_indicator("93.184.216.34", "ip")
    assert res_clean.raw_status == "CLEAN"
    assert res_clean.score == 0.0

    # URL indicator should be rejected by DNSBL without domain extraction
    res_url = provider.check_indicator("https://example.com/login", "url")
    assert res_url.raw_status == "UNSUPPORTED_TYPE"


def test_indicator_extraction_and_provenance():
    """Verify extracting domains, IPs, and URLs while preserving provenance."""
    parsed_email = ParsedEmail(
        message_id="msg-123",
        from_address=ParsedAddress(email="sender@evil-origin.com", domain="evil-origin.com", display_name="Sender"),
        to_addresses=[ParsedAddress(email="user@target.org", domain="target.org", display_name="User")],
        reply_to_addresses=[ParsedAddress(email="reply@attacker.net", domain="attacker.net", display_name="Reply")],
        received_hops=[
            ReceivedHop(
                from_host="mail.evil-origin.com (unknown [198.51.100.42])",
                by_host="mx.target.org",
                original_value="from mail.evil-origin.com (unknown [198.51.100.42]) by mx.target.org",
            )
        ],
        extracted_urls=[
            ExtractedUrl(
                original_url="https://phish.attacker.net/login?id=1",
                scheme="https",
                host="phish.attacker.net",
                path="/login",
            ),
            # Duplicate URL in body
            ExtractedUrl(
                original_url="https://phish.attacker.net/login?id=1",
                scheme="https",
                host="phish.attacker.net",
                path="/login",
            ),
            # URL with IP host
            ExtractedUrl(
                original_url="http://203.0.113.50/malware.exe",
                scheme="http",
                host="203.0.113.50",
                path="/malware.exe",
            ),
        ],
    )

    indicators = extract_indicators(parsed_email)

    values = {ind.value for ind in indicators}
    assert "evil-origin.com" in values
    assert "target.org" in values
    assert "attacker.net" in values
    assert "198.51.100.42" in values
    assert "phish.attacker.net" in values
    assert "203.0.113.50" in values
    assert "https://phish.attacker.net/login?id=1" in values
    assert "http://203.0.113.50/malware.exe" in values

    # Check provenance for evil-origin.com
    evil_ind = next(ind for ind in indicators if ind.value == "evil-origin.com")
    assert "header:From" in evil_ind.sources

    # Check provenance for 198.51.100.42
    ip_ind = next(ind for ind in indicators if ind.value == "198.51.100.42")
    assert "hop:Received[0]" in ip_ind.sources

    # Check deduplication: URLs should only appear once
    url_count = sum(1 for ind in indicators if ind.value == "https://phish.attacker.net/login?id=1")
    assert url_count == 1


def test_privacy_no_disk_writes_in_intelligence():
    """Verify intelligence module does not import tempfile or perform disk writes."""
    import inspect
    import intelligence
    import intelligence.enricher
    import intelligence.extractors
    import intelligence.dns.resolver
    import intelligence.rdap.client
    import intelligence.geoip.resolver
    import intelligence.reputation.service

    modules_to_check = [
        intelligence,
        intelligence.enricher,
        intelligence.extractors,
        intelligence.dns.resolver,
        intelligence.rdap.client,
        intelligence.geoip.resolver,
        intelligence.reputation.service,
    ]

    for mod in modules_to_check:
        src = inspect.getsource(mod)
        assert "tempfile" not in src, f"{mod.__name__} must not import tempfile"
        assert ".write(" not in src, f"{mod.__name__} must not write to files"
        assert "open(" not in src, f"{mod.__name__} should not use open()"
