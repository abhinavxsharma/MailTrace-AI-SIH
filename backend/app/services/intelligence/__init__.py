"""
MAILTRACE AI — Unified Intelligence Integration Service Package.

Orchestrates email parsing, header forensics, email authentication, DistilBERT ML inference,
threat intelligence enrichment, graph construction, campaign clustering, and timeline reconstruction.
"""

from __future__ import annotations

from app.services.intelligence.dependencies import (
    PipelineDependencies,
    create_default_dependencies,
)
from app.services.intelligence.models import (
    IntelligenceAnalysisResult,
    StageExecutionMetadata,
    StageStatus,
)
from app.services.intelligence.pipeline import IntelligencePipeline

__all__ = [
    "IntelligenceAnalysisResult",
    "IntelligencePipeline",
    "PipelineDependencies",
    "StageExecutionMetadata",
    "StageStatus",
    "create_default_dependencies",
]
