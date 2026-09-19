"""
MAILTRACE AI — Domain models for Campaign Clustering.

Defines structured records for grouped email campaigns.
All models are frozen Pydantic v2 models and operate strictly in memory.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field


class CampaignCluster(BaseModel):
    """
    Deterministic campaign grouping of correlated emails.

    Attributes:
        campaign_id: Deterministic identifier for the campaign.
        member_email_ids: List of email IDs belonging to this campaign.
        shared_indicators: List of indicators linking the emails together.
        correlation_reasons: List of correlation rule reasons that established the links.
        strength: Deterministic strength score (0.0 to 1.0) based on rule diversity and link density.
        evidence: Factual correlation evidence supporting this campaign cluster.
    """

    model_config = {"frozen": True}

    campaign_id: Annotated[str, Field(description="Deterministic campaign cluster ID")]
    member_email_ids: Annotated[
        list[str],
        Field(default_factory=list, description="IDs of member emails"),
    ]
    shared_indicators: Annotated[
        list[str],
        Field(default_factory=list, description="Shared indicators forming the cluster"),
    ]
    correlation_reasons: Annotated[
        list[str],
        Field(default_factory=list, description="Rules that connected the cluster members"),
    ]
    strength: Annotated[
        float,
        Field(default=0.0, description="Deterministic correlation strength (0.0 - 1.0)"),
    ] = 0.0
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Cluster provenance and supporting metadata"),
    ]
