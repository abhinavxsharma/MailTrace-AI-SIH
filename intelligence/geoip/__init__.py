"""
MAILTRACE AI — GeoIP Intelligence Package.

Provides IP geolocation resolution using provider abstractions and local databases.
"""

from __future__ import annotations

from intelligence.geoip.models import GeoIpResult, GeoIpStatus
from intelligence.geoip.resolver import (
    GeoIpProviderProtocol,
    GeoIpResolver,
    MaxMindGeoIpProvider,
    MissingDatabaseProvider,
    MockGeoIpProvider,
)

__all__ = [
    "GeoIpProviderProtocol",
    "GeoIpResolver",
    "GeoIpResult",
    "GeoIpStatus",
    "MaxMindGeoIpProvider",
    "MissingDatabaseProvider",
    "MockGeoIpProvider",
]
