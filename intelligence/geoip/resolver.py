"""
MAILTRACE AI — GeoIP Intelligence Resolver.

Provides IP geolocation resolution using a provider abstraction.
Supports local MaxMind / GeoLite2 databases when available, handles private/reserved
IPs gracefully, operates without external network in tests, and supports dependency injection.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Callable, Protocol

from intelligence.cache import InMemoryTtlCache
from intelligence.geoip.models import GeoIpResult, GeoIpStatus


class GeoIpProviderProtocol(Protocol):
    """Protocol defining a GeoIP resolution provider."""

    def lookup(self, ip_str: str) -> GeoIpResult:
        """Resolve geolocation details for an IP address."""
        ...


class MissingDatabaseProvider:
    """Default provider when no local database or external provider is configured."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path

    def lookup(self, ip_str: str) -> GeoIpResult:
        msg = f"GeoIP database file not found at: {self.db_path}" if self.db_path else "No GeoIP database configured"
        return GeoIpResult(
            ip=ip_str,
            status="DATABASE_MISSING",
            source="none",
            error=msg,
            evidence={"db_path": self.db_path},
        )


class MockGeoIpProvider:
    """Mock provider for unit tests and offline testing."""

    def __init__(
        self,
        data: dict[str, GeoIpResult] | None = None,
        mock_func: Callable[[str], GeoIpResult] | None = None,
    ):
        self.data = data or {}
        self.mock_func = mock_func

    def lookup(self, ip_str: str) -> GeoIpResult:
        if self.mock_func:
            return self.mock_func(ip_str)
        if ip_str in self.data:
            return self.data[ip_str]
        return GeoIpResult(
            ip=ip_str,
            status="NOT_FOUND",
            source="mock",
            error="IP not found in mock database",
        )


class MaxMindGeoIpProvider:
    """
    Provider utilizing a local MaxMind GeoLite2 / GeoIP2 database (.mmdb).
    Handles missing libraries or missing database files gracefully.
    """

    def __init__(self, city_db_path: str | None = None, asn_db_path: str | None = None):
        self.city_db_path = city_db_path
        self.asn_db_path = asn_db_path
        self._city_reader: Any = None
        self._asn_reader: Any = None
        self._init_error: str | None = None

        if not city_db_path or not os.path.isfile(city_db_path):
            self._init_error = f"City database not found: {city_db_path}"
            return

        try:
            import geoip2.database  # type: ignore

            self._city_reader = geoip2.database.Reader(city_db_path)
            if asn_db_path and os.path.isfile(asn_db_path):
                self._asn_reader = geoip2.database.Reader(asn_db_path)
        except ImportError:
            self._init_error = "geoip2 library is not installed"
        except Exception as exc:
            self._init_error = f"Failed to load MaxMind database: {exc}"

    def lookup(self, ip_str: str) -> GeoIpResult:
        if self._init_error:
            return GeoIpResult(
                ip=ip_str,
                status="DATABASE_MISSING",
                source="maxmind",
                error=self._init_error,
                evidence={"city_db_path": self.city_db_path},
            )

        try:
            response = self._city_reader.city(ip_str)
            country = response.country.iso_code or response.country.name
            region = response.subdivisions.most_specific.name if response.subdivisions else None
            city = response.city.name
            lat = response.location.latitude
            lon = response.location.longitude

            asn = None
            org = None
            if self._asn_reader:
                try:
                    asn_resp = self._asn_reader.asn(ip_str)
                    asn = str(asn_resp.autonomous_system_number) if asn_resp.autonomous_system_number else None
                    org = asn_resp.autonomous_system_organization
                except Exception:
                    pass

            return GeoIpResult(
                ip=ip_str,
                country=country,
                region=region,
                city=city,
                latitude=lat,
                longitude=lon,
                asn=asn,
                organization=org,
                source="maxmind",
                status="OK",
            )
        except Exception as exc:
            # e.g. AddressNotFoundError
            err_type = type(exc).__name__
            if "AddressNotFound" in err_type:
                return GeoIpResult(
                    ip=ip_str,
                    status="NOT_FOUND",
                    source="maxmind",
                    error="IP address not found in database",
                )
            return GeoIpResult(
                ip=ip_str,
                status="ERROR",
                source="maxmind",
                error=f"MaxMind lookup error: {err_type}: {exc}",
            )


class GeoIpResolver:
    """
    High-level GeoIP resolver service.

    Coordinates private IP checks, in-memory caching, and delegation to the
    configured provider.
    """

    def __init__(
        self,
        provider: GeoIpProviderProtocol | None = None,
        cache: InMemoryTtlCache[GeoIpResult] | None = None,
    ):
        self.provider = provider or MissingDatabaseProvider()
        self.cache = cache or InMemoryTtlCache[GeoIpResult](ttl_seconds=3600)

    def resolve(self, ip_str: str) -> GeoIpResult:
        """
        Resolve geolocation for an IP address.

        Args:
            ip_str: IPv4 or IPv6 string.

        Returns:
            ``GeoIpResult`` with location details or appropriate status.
        """
        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return GeoIpResult(
                ip=ip_str,
                status="MALFORMED",
                error=f"Invalid IP address format: {ip_str!r}",
                evidence={"reason": "invalid_ip_format"},
            )

        # Handle private / loopback / reserved IPs
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return GeoIpResult(
                ip=clean_ip,
                status="PRIVATE_IP",
                source="rfc1918_filter",
                evidence={"is_private": True, "ip_version": ip_obj.version},
            )

        # Check in-memory cache
        cached = self.cache.get(clean_ip)
        if cached is not None:
            return cached

        # Query provider
        try:
            result = self.provider.lookup(clean_ip)
        except Exception as exc:
            result = GeoIpResult(
                ip=clean_ip,
                status="ERROR",
                source="provider_exception",
                error=f"Unhandled provider error: {type(exc).__name__}: {exc}",
            )

        self.cache.set(clean_ip, result)
        return result
