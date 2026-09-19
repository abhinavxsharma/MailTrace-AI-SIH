"""
MAILTRACE AI — Unit tests for GeoIP intelligence.

Tests verify:
- Valid IP geolocation resolution (via mock provider)
- Missing database graceful handling (MissingDatabaseProvider)
- Unknown IP (NOT_FOUND) handling
- Provider error handling
- Private/reserved IP handling (PRIVATE_IP)
- Malformed IP handling (MALFORMED)
- MaxMindGeoIpProvider missing database file handling
- In-memory caching behavior
- Complete offline execution (no external network)
"""

from __future__ import annotations

import pytest

from intelligence.cache import InMemoryTtlCache
from intelligence.geoip.models import GeoIpResult
from intelligence.geoip.resolver import (
    GeoIpResolver,
    MaxMindGeoIpProvider,
    MissingDatabaseProvider,
    MockGeoIpProvider,
)


def test_geoip_result_immutability():
    """Verify GeoIpResult is frozen."""
    res = GeoIpResult(
        ip="8.8.8.8",
        country="US",
        city="Mountain View",
        status="OK",
    )
    assert res.ip == "8.8.8.8"
    assert res.country == "US"
    with pytest.raises(Exception):
        res.city = "Other"  # type: ignore


def test_geoip_valid_lookup_mock():
    """Verify valid GeoIP lookup using mock provider."""
    mock_data = {
        "93.184.216.34": GeoIpResult(
            ip="93.184.216.34",
            country="US",
            region="California",
            city="Los Angeles",
            latitude=34.0522,
            longitude=-118.2437,
            asn="AS15133",
            organization="MCI Communications Services",
            source="mock",
            status="OK",
        )
    }
    provider = MockGeoIpProvider(data=mock_data)
    resolver = GeoIpResolver(provider=provider)

    result = resolver.resolve("93.184.216.34")

    assert result.status == "OK"
    assert result.country == "US"
    assert result.region == "California"
    assert result.city == "Los Angeles"
    assert result.latitude == 34.0522
    assert result.longitude == -118.2437
    assert result.asn == "AS15133"
    assert result.organization == "MCI Communications Services"


def test_geoip_missing_database_graceful():
    """Verify missing database returns DATABASE_MISSING status gracefully."""
    provider = MissingDatabaseProvider(db_path="/nonexistent/GeoLite2-City.mmdb")
    resolver = GeoIpResolver(provider=provider)

    result = resolver.resolve("8.8.8.8")

    assert result.status == "DATABASE_MISSING"
    assert result.country is None
    assert "not found" in str(result.error).lower()


def test_geoip_maxmind_provider_missing_file():
    """Verify MaxMindGeoIpProvider handles missing .mmdb file gracefully."""
    provider = MaxMindGeoIpProvider(city_db_path="nonexistent_db.mmdb")
    res = provider.lookup("8.8.8.8")

    assert res.status == "DATABASE_MISSING"
    assert "not found" in str(res.error).lower()


def test_geoip_unknown_ip():
    """Verify IP not found in provider returns NOT_FOUND."""
    provider = MockGeoIpProvider(data={})
    resolver = GeoIpResolver(provider=provider)

    result = resolver.resolve("8.8.8.8")

    assert result.status == "NOT_FOUND"
    assert result.country is None


def test_geoip_private_ip_detection():
    """Verify private and loopback IPs return PRIVATE_IP without querying provider."""
    mock_called = False

    def mock_lookup(ip: str) -> GeoIpResult:
        nonlocal mock_called
        mock_called = True
        return GeoIpResult(ip=ip, status="OK")

    provider = MockGeoIpProvider(mock_func=mock_lookup)
    resolver = GeoIpResolver(provider=provider)

    private_ips = [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.100",
        "172.16.50.1",
        "169.254.1.1",
        "::1",
    ]

    for pip in private_ips:
        res = resolver.resolve(pip)
        assert res.status == "PRIVATE_IP"
        assert res.source == "rfc1918_filter"
        assert res.country is None

    assert not mock_called, "Provider should not be called for private IP addresses"


def test_geoip_malformed_ip():
    """Verify malformed IP strings return MALFORMED status."""
    resolver = GeoIpResolver()

    res1 = resolver.resolve("not-an-ip")
    assert res1.status == "MALFORMED"

    res2 = resolver.resolve("999.999.999.999")
    assert res2.status == "MALFORMED"

    res3 = resolver.resolve("")
    assert res3.status == "MALFORMED"


def test_geoip_provider_error_handling():
    """Verify unhandled provider exception is caught safely as ERROR."""
    def broken_lookup(ip: str) -> GeoIpResult:
        raise RuntimeError("Disk read error or corrupted file")

    provider = MockGeoIpProvider(mock_func=broken_lookup)
    resolver = GeoIpResolver(provider=provider)

    result = resolver.resolve("8.8.8.8")

    assert result.status == "ERROR"
    assert "RuntimeError" in str(result.error)


def test_geoip_caching():
    """Verify caching prevents repeated provider lookups."""
    call_count = 0

    def mock_lookup(ip: str) -> GeoIpResult:
        nonlocal call_count
        call_count += 1
        return GeoIpResult(ip=ip, country="CA", status="OK")

    cache = InMemoryTtlCache[GeoIpResult](ttl_seconds=300)
    resolver = GeoIpResolver(provider=MockGeoIpProvider(mock_func=mock_lookup), cache=cache)

    res1 = resolver.resolve("93.184.216.34")
    assert res1.status == "OK"
    assert call_count == 1

    res2 = resolver.resolve("93.184.216.34")
    assert res2.status == "OK"
    assert res2.country == "CA"
    assert call_count == 1
