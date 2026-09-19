"""
MAILTRACE AI — Domain models for Unified Intelligence Pipeline.

Defines the structured result container aggregating all forensic, authentication,
ML, threat intelligence, graph, campaign, and timeline analysis for an email.
All models are frozen Pydantic v2 models and operate strictly in memory.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from forensics.authentication.models import AuthenticationResult
from forensics.email_parser.models import ParsedEmail
from forensics.headers.models import HeaderForensicResult
from graph.campaign.models import CampaignCluster
from graph.correlation.models import CorrelationMatch, EmailGraph
from graph.timeline.models import EmailTimeline
from intelligence.models import EmailIntelligenceResult
from ml.inference.models import MlClassificationResult

StageStatus = Literal[
    "SUCCESS",
    "FAILED",
    "SKIPPED",
    "PARTIAL",
    "UNAVAILABLE",
]


class StageExecutionMetadata(BaseModel):
    """
    Execution metadata and diagnostic status for an individual pipeline stage.

    Attributes:
        stage_name: Name of the pipeline stage.
        status: Execution outcome (SUCCESS, FAILED, SKIPPED, PARTIAL, UNAVAILABLE).
        duration_ms: Time spent executing the stage in milliseconds.
        error: Error message or description if the stage encountered an issue.
        details: Optional diagnostic details.
    """

    model_config = {"frozen": True}

    stage_name: Annotated[str, Field(description="Pipeline stage name")]
    status: Annotated[StageStatus, Field(description="Stage execution status")]
    duration_ms: Annotated[float, Field(default=0.0, description="Stage duration in milliseconds")] = 0.0
    error: Annotated[str | None, Field(default=None, description="Error message if stage failed")] = None
    details: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Diagnostic details"),
    ]


class IntelligenceAnalysisResult(BaseModel):
    """
    Unified structured intelligence analysis result for an email.

    Aggregates all component evidence across forensics, authentication, ML classification,
    threat intelligence, graph entities, campaign clustering, and timeline reconstruction.
    """

    model_config = {"frozen": True}

    message_id: Annotated[str, Field(description="Primary message identifier")]
    provider_message_id: Annotated[str | None, Field(default=None, description="Mail provider message ID")] = None
    thread_id: Annotated[str | None, Field(default=None, description="Mail provider thread ID")] = None
    subject: Annotated[str | None, Field(default=None, description="Email subject line")] = None
    date: Annotated[str | None, Field(default=None, description="Origination date string")] = None

    # Pipeline Diagnostics
    stages: Annotated[
        dict[str, StageExecutionMetadata],
        Field(default_factory=dict, description="Execution status for each stage"),
    ]

    # Component Results
    parsed_email: Annotated[
        ParsedEmail | None,
        Field(default=None, description="Parsed email from Chunk 2"),
    ] = None
    header_forensics: Annotated[
        HeaderForensicResult | None,
        Field(default=None, description="Header forensics result from Chunk 2"),
    ] = None
    authentication: Annotated[
        AuthenticationResult | None,
        Field(default=None, description="SPF/DKIM/DMARC verification result from Chunk 3"),
    ] = None
    ml_classification: Annotated[
        MlClassificationResult | None,
        Field(default=None, description="DistilBERT phishing inference from Chunk 4"),
    ] = None
    threat_intelligence: Annotated[
        EmailIntelligenceResult | None,
        Field(default=None, description="Enriched DNS/RDAP/GeoIP/Reputation from Chunk 5"),
    ] = None
    graph: Annotated[
        EmailGraph | None,
        Field(default=None, description="Entity-relationship graph from Chunk 6"),
    ] = None
    correlations: Annotated[
        list[CorrelationMatch],
        Field(default_factory=list, description="Cross-email correlation matches from Chunk 6"),
    ]
    campaign: Annotated[
        CampaignCluster | None,
        Field(default=None, description="Campaign cluster membership from Chunk 6"),
    ] = None
    timeline: Annotated[
        EmailTimeline | None,
        Field(default=None, description="Chronological timeline from Chunk 6"),
    ] = None

    # Global Status and Provenance
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Unified intelligence evidence metadata"),
    ]
    success: Annotated[
        bool,
        Field(default=True, description="True if core parsing and analysis succeeded"),
    ] = True
    errors: Annotated[
        list[str],
        Field(default_factory=list, description="List of stage failure errors"),
    ]
