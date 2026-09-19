"""
MAILTRACE AI — Domain models for Threat Reputation.

Defines structured records for domain, IP, and URL reputation checks.
All models are frozen Pydantic v2 models.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

ReputationStatus = Literal[
    "CLEAN",
    "SUSPICIOUS",
    "MALICIOUS",
    "NOT_CONFIGURED",
    "UNAVAILABLE",
    "ERROR",
]

IndicatorType = Literal["domain", "ip", "url"]


class ReputationResult(BaseModel):
    """
    Structured reputation result from a specific provider.

    Attributes:
        indicator: Queried indicator string (domain, IP, or URL).
        indicator_type: Type of indicator (domain, ip, url).
        provider: Provider identifier (e.g., 'dnsbl_spamhaus', 'mock', 'none').
        score: Normalized or provider-supplied score if provided.
        category: Threat category if reported (e.g. 'phishing', 'malware', 'spam').
        confidence: Provider confidence level if supplied.
        raw_status: Raw provider response or status code.
        evidence: Metadata and supporting evidence.
    """

    model_config = {"frozen": True}

    indicator: Annotated[str, Field(description="Queried indicator string")]
    indicator_type: Annotated[IndicatorType, Field(description="Type of indicator (domain, ip, url)")]
    provider: Annotated[str, Field(description="Reputation provider name")]
    score: Annotated[float | None, Field(default=None, description="Score if supplied by provider")] = None
    category: Annotated[str | None, Field(default=None, description="Threat category")] = None
    confidence: Annotated[float | None, Field(default=None, description="Confidence if supplied")] = None
    raw_status: Annotated[str, Field(default="NOT_CONFIGURED", description="Raw status or provider status")] = "NOT_CONFIGURED"
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Metadata and supporting evidence"),
    ]


class AggregatedReputationResult(BaseModel):
    """
    Combined reputation results across multiple providers for an indicator.
    """

    model_config = {"frozen": True}

    indicator: Annotated[str, Field(description="Queried indicator string")]
    indicator_type: Annotated[IndicatorType, Field(description="Type of indicator")]
    results: Annotated[
        list[ReputationResult],
        Field(default_factory=list, description="List of provider results"),
    ]
    status: Annotated[str, Field(default="NOT_CONFIGURED", description="Aggregated status")] = "NOT_CONFIGURED"
    summary: Annotated[str, Field(default="", description="Human-readable summary")] = ""
