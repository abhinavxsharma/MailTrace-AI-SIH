"""
MAILTRACE AI — Domain models for RDAP intelligence.

Defines structured records for domain and IP registration/network lookups via RDAP.
All models are frozen Pydantic v2 models.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

RdapStatus = Literal[
    "OK",
    "NOT_FOUND",
    "TIMEOUT",
    "MALFORMED",
    "ERROR",
    "UNAVAILABLE",
]

RdapQueryType = Literal["domain", "ip"]


class RdapResult(BaseModel):
    """
    Structured result of an RDAP registration or network query.

    Attributes:
        query: Queried domain or IP.
        query_type: Type of query ("domain" or "ip").
        status: Query status (OK, NOT_FOUND, TIMEOUT, MALFORMED, ERROR, UNAVAILABLE).
        registrar: Registrar or registry name if available.
        organization: Organization or entity name if available.
        country: Country code or name if available.
        registration_date: Registration / creation timestamp if available.
        expiration_date: Expiration timestamp if available.
        last_changed_date: Last updated timestamp if available.
        nameservers: List of nameserver hostnames if available.
        network_cidr: Network CIDR block (for IP queries) if available.
        asn: Autonomous System Number if available.
        source: Information source (e.g. "rdap.org", "mock").
        error: Error details if query was unsuccessful.
        raw_data: Parsed summary from the RDAP response.
        evidence: Metadata, timing, and response headers.
    """

    model_config = {"frozen": True}

    query: Annotated[str, Field(description="Queried domain or IP address")]
    query_type: Annotated[RdapQueryType, Field(description="Indicator type (domain or ip)")]
    status: Annotated[RdapStatus, Field(description="RDAP query status")]
    registrar: Annotated[str | None, Field(default=None, description="Registrar / registry name")] = None
    organization: Annotated[str | None, Field(default=None, description="Registrant or entity organization")] = None
    country: Annotated[str | None, Field(default=None, description="Country associated with registration")] = None
    registration_date: Annotated[str | None, Field(default=None, description="Creation timestamp")] = None
    expiration_date: Annotated[str | None, Field(default=None, description="Expiration timestamp")] = None
    last_changed_date: Annotated[str | None, Field(default=None, description="Last update timestamp")] = None
    nameservers: Annotated[
        list[str],
        Field(default_factory=list, description="Nameservers"),
    ]
    network_cidr: Annotated[str | None, Field(default=None, description="Network CIDR if IP query")] = None
    asn: Annotated[str | None, Field(default=None, description="Autonomous System Number")] = None
    source: Annotated[str, Field(default="rdap", description="RDAP service source")] = "rdap"
    error: Annotated[str | None, Field(default=None, description="Error message if query failed")] = None
    raw_data: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Parsed RDAP response fields"),
    ]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Query timing and execution evidence"),
    ]
