"""
MAILTRACE AI — Unified Intelligence Integration Service Package.

Orchestrates email parsing, header forensics, email authentication, DistilBERT ML inference,
threat intelligence enrichment, graph construction, campaign clustering, and timeline reconstruction.
"""

from __future__ import annotations

try:
    from backend.app.services.intelligence.dependencies import (
        PipelineDependencies,
        create_default_dependencies,
    )
    from backend.app.services.intelligence.models import (
        IntelligenceAnalysisResult,
        StageExecutionMetadata,
        StageStatus,
    )
    from backend.app.services.intelligence.pipeline import IntelligencePipeline
except ImportError:
    try:
        from app.services.intelligence.dependencies import (  # type: ignore
            PipelineDependencies,
            create_default_dependencies,
        )
        from app.services.intelligence.models import (  # type: ignore
            IntelligenceAnalysisResult,
            StageExecutionMetadata,
            StageStatus,
        )
        from app.services.intelligence.pipeline import IntelligencePipeline  # type: ignore
    except ImportError:
        PipelineDependencies = None  # type: ignore
        create_default_dependencies = None  # type: ignore
        IntelligenceAnalysisResult = None  # type: ignore
        StageExecutionMetadata = None  # type: ignore
        StageStatus = None  # type: ignore
        IntelligencePipeline = None  # type: ignore

from backend.app.services.intelligence.nlp_intent import NlpThreatIntent, extract_threat_intents
from backend.app.services.intelligence.nlp_entities import ExtractedEntity, extract_entities
from backend.app.services.intelligence.semantic_correlation import (
    SemanticCampaignIntelligence,
    SemanticCampaignMatch,
    correlate_semantic_campaigns,
)

__all__ = [
    "IntelligenceAnalysisResult",
    "IntelligencePipeline",
    "PipelineDependencies",
    "StageExecutionMetadata",
    "StageStatus",
    "create_default_dependencies",
    "NlpThreatIntent",
    "extract_threat_intents",
    "ExtractedEntity",
    "extract_entities",
    "SemanticCampaignIntelligence",
    "SemanticCampaignMatch",
    "correlate_semantic_campaigns",
]
