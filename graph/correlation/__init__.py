"""
MAILTRACE AI — Correlation and Graph Package.

Provides graph entity models, relationship definitions, and deterministic correlation engines.
"""

from __future__ import annotations

from graph.correlation.engine import CorrelationEngine
from graph.correlation.models import (
    AnalyzedEmailContext,
    CorrelationMatch,
    EmailGraph,
    EntityType,
    GraphEntity,
    GraphRelationship,
    RelationshipType,
)

__all__ = [
    "AnalyzedEmailContext",
    "CorrelationEngine",
    "CorrelationMatch",
    "EmailGraph",
    "EntityType",
    "GraphEntity",
    "GraphRelationship",
    "RelationshipType",
]
