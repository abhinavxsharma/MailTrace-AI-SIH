"""
MAILTRACE AI — Unit tests for RDAP intelligence client.

Tests verify:
- Valid domain RDAP response parsing
- Valid IP RDAP response parsing
- Missing / partial fields handling
- HTTP 404 (NOT_FOUND) handling
- HTTP 500 / failure handling
- Timeout handling
- Malformed JSON / response handling
- Private/reserved IP handling (RFC 1918)
- In-memory caching
- Complete offline mock HTTP execution
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from intelligence.cache import InMemoryTtlCache
from intelligence.rdap.client import RdapClient
from intelligence.rdap.models import RdapResult


def test_rdap_result_immutability():
    """Verify RdapResult is frozen."""
    res = RdapResult(
        query="example.com",
        query_type="domain",
        status="OK",
        registrar="Example Registrar Inc.",
    )
    assert res.query == "example.com"
    assert res.registrar == "Example Registrar Inc."
    with pytest.raises(Exception):
        res.registrar = "Another"  # type: ignore


def test_rdap_domain_valid_response():
    """Verify parsing a complete, standard domain RDAP response."""
    mock_rdap_domain = {
        "handle": "example.com",
        "ldhName": "EXAMPLE.COM",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2024-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2023-08-14T07:01:38Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Internet Assigned Numbers Authority"],
                    ],
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["org", {}, "text", "Internet Corporation for Assigned Names and Numbers"],
                    ],
                ],
            },
        ],
        "nameservers": [
            {"ldhName": "a.iana-servers.net"},
            {"ldhName": "b.iana-servers.net"},
        ],
    }

    def mock_fetch(url: str) -> tuple[int, dict[str, Any]]:
        return 200, mock_rdap_domain

    client = RdapClient(mock_fetch_func=mock_fetch)
    result = client.lookup_domain("example.com")

    assert result.status == "OK"
    assert result.query == "example.com"
    assert result.query_type == "domain"
    assert result.registrar == "Internet Assigned Numbers Authority"
    assert result.organization == "Internet Corporation for Assigned Names and Numbers"
    assert result.registration_date == "1995-08-14T04:00:00Z"
    assert result.expiration_date == "2024-08-13T04:00:00Z"
    assert result.last_changed_date == "2023-08-14T07:01:38Z"
    assert "a.iana-servers.net" in result.nameservers
    assert "b.iana-servers.net" in result.nameservers


def test_rdap_ip_valid_response():
    """Verify parsing a valid IP RDAP response."""
    mock_rdap_ip = {
        "handle": "NET-93-184-216-0-1",
        "startAddress": "93.184.216.0",
        "endAddress": "93.184.216.255",
        "ipVersion": "v4",
        "country": "US",
        "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "EDGECAST-NETWORKS"],
                    ],
                ],
            }
        ],
    }

    def mock_fetch(url: str) -> tuple[int, dict[str, Any]]:
        return 200, mock_rdap_ip

    client = RdapClient(mock_fetch_func=mock_fetch)
    result = client.lookup_ip("93.184.216.34")

    assert result.status == "OK"
    assert result.query == "93.184.216.34"
    assert result.query_type == "ip"
    assert result.country == "US"
    assert result.network_cidr == "93.184.216.0/24"
    assert result.organization == "EDGECAST-NETWORKS"


def test_rdap_missing_optional_fields():
    """Verify handling when optional RDAP fields are absent."""
    minimal_rdap = {
        "handle": "MINIMAL-DOMAIN",
    }

    def mock_fetch(url: str) -> tuple[int, dict[str, Any]]:
        return 200, minimal_rdap

    client = RdapClient(mock_fetch_func=mock_fetch)
    result = client.lookup_domain("minimal.example")

    assert result.status == "OK"
    assert result.registrar is None
    assert result.organization is None
    assert result.registration_date is None
    assert result.nameservers == []


def test_rdap_http_not_found():
    """Verify HTTP 404 maps to NOT_FOUND."""
    def mock_fetch(url: str) -> tuple[int, dict[str, Any]]:
        return 404, {"errorCode": 404, "title": "Not Found"}

    client = RdapClient(mock_fetch_func=mock_fetch)
    result = client.lookup_domain("notfound.example")

    assert result.status == "NOT_FOUND"
    assert "404" in str(result.error)


def test_rdap_http_server_error():
    """Verify HTTP 500 maps to ERROR."""
    def mock_fetch(url: str) -> tuple[int, dict[str, Any]]:
        return 500, {"errorCode": 500, "title": "Internal Server Error"}

    client = RdapClient(mock_fetch_func=mock_fetch)
    result = client.lookup_domain("error.example")

    assert result.status == "ERROR"
    assert "500" in str(result.error)


def test_rdap_timeout_handling():
    """Verify timeout is caught and handled."""
    import httpx

    def mock_fetch(url: str) -> tuple[int, dict[str, Any]]:
        raise httpx.TimeoutException("Connection timed out")

    client = RdapClient(mock_fetch_func=mock_fetch)
    result = client.lookup_domain("timeout.example")

    assert result.status == "TIMEOUT"
    assert "timed out" in str(result.error).lower()


def test_rdap_malformed_json_handling():
    """Verify malformed JSON string response is handled as MALFORMED."""
    def mock_fetch(url: str) -> tuple[int, str]:
        return 200, "{ invalid json ... "

    client = RdapClient(mock_fetch_func=mock_fetch)
    result = client.lookup_domain("malformed.example")

    assert result.status == "MALFORMED"
    assert "malformed" in str(result.error).lower()


def test_rdap_private_ip_handling():
    """Verify private/reserved IPs return RFC1918 indicator without external HTTP lookup."""
    fetch_called = False

    def mock_fetch(url: str) -> tuple[int, dict[str, Any]]:
        nonlocal fetch_called
        fetch_called = True
        return 200, {}

    client = RdapClient(mock_fetch_func=mock_fetch)
    for priv_ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "::1"]:
        res = client.lookup_ip(priv_ip)
        assert res.status == "OK"
        assert "Private" in str(res.organization)
        assert res.source == "rfc1918_filter"

    assert not fetch_called, "Private IP lookups should never make external HTTP requests"


def test_rdap_caching():
    """Verify caching prevents repeated HTTP requests."""
    fetch_count = 0

    def mock_fetch(url: str) -> tuple[int, dict[str, Any]]:
        nonlocal fetch_count
        fetch_count += 1
        return 200, {"handle": "CACHED"}

    cache = InMemoryTtlCache[RdapResult](ttl_seconds=300)
    client = RdapClient(cache=cache, mock_fetch_func=mock_fetch)

    res1 = client.lookup_domain("cache-test.example")
    assert res1.status == "OK"
    assert fetch_count == 1

    res2 = client.lookup_domain("cache-test.example")
    assert res2.status == "OK"
    assert fetch_count == 1
