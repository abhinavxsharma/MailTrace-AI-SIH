"""
MAILTRACE AI — Domain models for Graph, Correlation, and Relationship Intelligence.

Defines typed entities, relationships, correlation matches, and analysis contexts.
All models are frozen Pydantic v2 models and operate strictly in memory.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from forensics.authentication.models import AuthenticationResult
from forensics.email_parser.models import ParsedEmail
from intelligence.models import EmailIntelligenceResult
from ml.inference.models import MlClassificationResult

EntityType = Literal[
    "email",
    "address",
    "domain",
    "ip",
    "url",
    "message_id",
    "dkim_domain",
    "spf_domain",
    "rdap_network",
    "campaign",
]

RelationshipType = Literal[
    "EMAIL_SENT_BY_ADDRESS",
    "EMAIL_TARGETS_ADDRESS",
    "EMAIL_REPLIES_TO",
    "EMAIL_REFERENCES",
    "EMAIL_USES_DOMAIN",
    "EMAIL_CONTAINS_URL",
    "URL_HOSTS_DOMAIN",
    "DOMAIN_RESOLVES_TO_IP",
    "EMAIL_RECEIVED_FROM_IP",
    "DOMAIN_REGISTERED_TO_NETWORK",
    "EMAIL_HAS_DKIM_DOMAIN",
    "EMAIL_HAS_SPF_DOMAIN",
    "EMAIL_PART_OF_CAMPAIGN",
]


class GraphEntity(BaseModel):
    """
    Structured node in the email intelligence graph.

    Attributes:
        id: Unique identifier for the entity (e.g., 'email:msg-123', 'domain:example.com').
        type: Entity category (email, address, domain, ip, url, etc.).
        display_value: Human-readable representation.
        evidence: Factual provenance and context for this entity.
    """

    model_config = {"frozen": True}

    id: Annotated[str, Field(description="Unique entity identifier")]
    type: Annotated[str, Field(description="Entity category")]
    display_value: Annotated[str, Field(description="Human-readable label")]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Entity extraction context and evidence"),
    ]


class GraphRelationship(BaseModel):
    """
    Directed edge between two entities in the intelligence graph.

    Attributes:
        source_id: ID of the originating entity.
        target_id: ID of the destination entity.
        relationship_type: Type of connection.
        evidence: Provenance and supporting context for the edge.
    """

    model_config = {"frozen": True}

    source_id: Annotated[str, Field(description="Originating entity ID")]
    target_id: Annotated[str, Field(description="Destination entity ID")]
    relationship_type: Annotated[str, Field(description="Relationship category")]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Supporting evidence for relationship"),
    ]


class CorrelationMatch(BaseModel):
    """
    Factual correlation match between two emails based on a deterministic rule.

    Attributes:
        email_id_1: First email identifier.
        email_id_2: Second email identifier.
        reason: Rule identifier (e.g. 'shared_domain', 'shared_url', 'shared_ip').
        shared_indicator: The specific indicator value that triggered the match.
        evidence: Factual proof of the correlation.
    """

    model_config = {"frozen": True}

    email_id_1: Annotated[str, Field(description="First email message ID")]
    email_id_2: Annotated[str, Field(description="Second email message ID")]
    reason: Annotated[str, Field(description="Explainable correlation rule reason")]
    shared_indicator: Annotated[str, Field(description="Matched indicator value")]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Correlation provenance and proof"),
    ]


class EmailGraph(BaseModel):
    """
    Graph representation of an individual email or sub-cluster.

    Attributes:
        entities: Deduplicated list of graph nodes.
        relationships: Deduplicated list of graph edges.
        evidence: Graph construction metadata.
    """

    model_config = {"frozen": True}

    entities: Annotated[
        list[GraphEntity],
        Field(default_factory=list, description="All graph nodes"),
    ]
    relationships: Annotated[
        list[GraphRelationship],
        Field(default_factory=list, description="All graph edges"),
    ]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Graph construction metadata"),
    ]


class AnalyzedEmailContext(BaseModel):
    """
    Aggregate container holding an email and its completed forensic/intelligence analysis.

    Provides the complete input required for graph generation, correlation,
    campaign clustering, and timeline construction.
    """

    model_config = {"frozen": True}

    parsed_email: Annotated[ParsedEmail, Field(description="Parsed email from Chunk 2")]
    auth_result: Annotated[
        AuthenticationResult | None,
        Field(default=None, description="SPF/DKIM/DMARC authentication result from Chunk 3"),
    ] = None
    ml_result: Annotated[
        MlClassificationResult | None,
        Field(default=None, description="DistilBERT ML classification result from Chunk 4"),
    ] = None
    intel_result: Annotated[
        EmailIntelligenceResult | None,
        Field(default=None, description="Enriched threat intelligence from Chunk 5"),
    ] = None
