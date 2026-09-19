"""
MAILTRACE AI — Graph, Campaign, and Timeline Intelligence Package.

Provides in-memory typed graph representations, deterministic correlation rules,
rule-based campaign clustering, and chronological timeline reconstruction.
Operates strictly in memory and does not compute a final risk score.
"""

from __future__ import annotations

from graph.campaign import CampaignCluster, CampaignClusterer
from graph.correlation import (
    AnalyzedEmailContext,
    CorrelationEngine,
    CorrelationMatch,
    EmailGraph,
    EntityType,
    GraphEntity,
    GraphRelationship,
    RelationshipType,
)
from graph.timeline import EmailTimeline, TimelineBuilder, TimelineEvent

__all__ = [
    "AnalyzedEmailContext",
    "CampaignCluster",
    "CampaignClusterer",
    "CorrelationEngine",
    "CorrelationMatch",
    "EmailGraph",
    "EmailTimeline",
    "EntityType",
    "GraphEntity",
    "GraphRelationship",
    "RelationshipType",
    "TimelineBuilder",
    "TimelineEvent",
]
