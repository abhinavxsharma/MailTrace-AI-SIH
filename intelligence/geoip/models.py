"""
MAILTRACE AI — Domain models for GeoIP intelligence.

Defines structured records for IP geolocation lookups.
All models are frozen Pydantic v2 models.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

GeoIpStatus = Literal[
    "OK",
    "PRIVATE_IP",
    "DATABASE_MISSING",
    "NOT_FOUND",
    "MALFORMED",
    "ERROR",
]


class GeoIpResult(BaseModel):
    """
    Structured result of an IP geolocation query.

    Attributes:
        ip: Queried IP address string.
        country: Two-letter ISO country code or country name.
        region: State, province, or region name.
        city: City name.
        latitude: Estimated geographic latitude.
        longitude: Estimated geographic longitude.
        asn: Autonomous System Number if available.
        organization: Autonomous System Organization or ISP name.
        source: Information source (e.g., 'maxmind_city', 'mock', 'rfc1918').
        status: Lookup status (OK, PRIVATE_IP, DATABASE_MISSING, NOT_FOUND, MALFORMED, ERROR).
        error: Error details if query failed.
        evidence: Resolution metadata.
    """

    model_config = {"frozen": True}

    ip: Annotated[str, Field(description="Queried IP address")]
    country: Annotated[str | None, Field(default=None, description="Country code or name")] = None
    region: Annotated[str | None, Field(default=None, description="Region or state")] = None
    city: Annotated[str | None, Field(default=None, description="City")] = None
    latitude: Annotated[float | None, Field(default=None, description="Latitude")] = None
    longitude: Annotated[float | None, Field(default=None, description="Longitude")] = None
    asn: Annotated[str | None, Field(default=None, description="Autonomous System Number")] = None
    organization: Annotated[str | None, Field(default=None, description="Network / ASN organization")] = None
    source: Annotated[str, Field(default="geoip", description="GeoIP data source")] = "geoip"
    status: Annotated[GeoIpStatus, Field(description="GeoIP lookup status")]
    error: Annotated[str | None, Field(default=None, description="Error message if failed")] = None
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Resolution metadata"),
    ]
