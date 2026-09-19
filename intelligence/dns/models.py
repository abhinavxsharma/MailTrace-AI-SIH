"""
MAILTRACE AI — Domain models for DNS intelligence.

Defines structured records and intelligence containers for DNS lookups.
All models are frozen Pydantic v2 models.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

DnsStatus = Literal[
    "NOERROR",
    "NXDOMAIN",
    "SERVFAIL",
    "TIMEOUT",
    "NO_RECORDS",
    "MALFORMED",
    "ERROR",
]


class DnsRecordResult(BaseModel):
    """
    Structured result of an individual DNS record query.

    Attributes:
        domain: Queried domain name.
        record_type: Record type (A, AAAA, MX, NS, TXT, CNAME).
        values: List of string values returned for the record.
        resolver: Resolver identifier (e.g. 'system', '8.8.8.8', 'mock').
        status: Query status (NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT, NO_RECORDS, MALFORMED, ERROR).
        error: Detailed error message if status is not NOERROR.
        evidence: Metadata and query timing.
    """

    model_config = {"frozen": True}

    domain: Annotated[str, Field(description="Queried domain")]
    record_type: Annotated[str, Field(description="DNS record type (A, AAAA, MX, NS, TXT, CNAME)")]
    values: Annotated[
        list[str],
        Field(default_factory=list, description="Resolved record values"),
    ]
    resolver: Annotated[str, Field(default="system", description="Resolver used")] = "system"
    status: Annotated[DnsStatus, Field(description="Resolution status")]
    error: Annotated[str | None, Field(default=None, description="Error details if lookup failed")] = None
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Query timing and resolution metadata"),
    ]


class DnsIntelligenceResult(BaseModel):
    """
    Comprehensive DNS intelligence for a domain across standard record types.
    """

    model_config = {"frozen": True}

    domain: Annotated[str, Field(description="Queried domain")]
    records: Annotated[
        dict[str, DnsRecordResult],
        Field(default_factory=dict, description="Record results keyed by record type"),
    ]
    a_records: Annotated[list[str], Field(default_factory=list, description="IPv4 addresses (A)")]
    aaaa_records: Annotated[list[str], Field(default_factory=list, description="IPv6 addresses (AAAA)")]
    mx_records: Annotated[list[str], Field(default_factory=list, description="Mail exchangers (MX)")]
    ns_records: Annotated[list[str], Field(default_factory=list, description="Name servers (NS)")]
    txt_records: Annotated[list[str], Field(default_factory=list, description="Text records (TXT)")]
    cname_records: Annotated[list[str], Field(default_factory=list, description="Canonical names (CNAME)")]
    status: Annotated[str, Field(default="NOERROR", description="Overall domain status")] = "NOERROR"
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Resolution metadata"),
    ]
