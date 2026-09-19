"""
MAILTRACE AI — Domain models for threat intelligence and indicator enrichment.

Defines extracted indicators with source provenance and the structured
aggregated intelligence result container.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

IndicatorType = Literal["domain", "ip", "url"]


class ExtractedIndicator(BaseModel):
    """
    Structured indicator extracted from an email with full provenance.

    Attributes:
        value: The indicator string (e.g. 'example.com', '192.0.2.1', 'https://example.com/login').
        indicator_type: Category ('domain', 'ip', or 'url').
        sources: List of provenance locations where this indicator appeared
                 (e.g. ['header:From', 'body:URL', 'hop:Received[0]']).
        context: Optional dictionary containing additional extraction context.
    """

    model_config = {"frozen": True}

    value: Annotated[str, Field(description="Normalized indicator value")]
    indicator_type: Annotated[IndicatorType, Field(description="Indicator category: domain, ip, or url")]
    sources: Annotated[
        list[str],
        Field(default_factory=list, description="List of source locations (provenance)"),
    ]
    context: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Extraction context and metadata"),
    ]


class EmailIntelligenceResult(BaseModel):
    """
    Comprehensive structured intelligence evidence for an email.

    Aggregates indicators, DNS intelligence, RDAP registrations, GeoIP locations,
    and reputation lookups.
    """

    model_config = {"frozen": True}

    indicators: Annotated[
        list[ExtractedIndicator],
        Field(default_factory=list, description="All deduplicated indicators with provenance"),
    ]
    dns: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="DNS intelligence results keyed by domain"),
    ]
    rdap: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="RDAP registration results keyed by indicator"),
    ]
    geoip: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="GeoIP location results keyed by IP"),
    ]
    reputation: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Reputation provider results keyed by indicator"),
    ]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Aggregated factual intelligence evidence"),
    ]
