"""
MAILTRACE AI — Dependency Injection Container for Intelligence Pipeline.

Provides injectable services and providers for threat intelligence, ML,
authentication, graph correlation, campaign clustering, and timeline reconstruction.
Supports 100% offline mock injection for automated tests.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from forensics.authentication.spf import DnsResolverProtocol
from graph.campaign.clustering import CampaignClusterer
from graph.correlation.engine import CorrelationEngine
from graph.correlation.models import AnalyzedEmailContext
from graph.timeline.builder import TimelineBuilder
from intelligence.dns.resolver import DnsIntelligenceResolver
from intelligence.enricher import EmailIntelligenceEnricher
from intelligence.geoip.resolver import GeoIpResolver
from intelligence.rdap.client import RdapClient
from intelligence.reputation.service import ReputationService
from ml.inference.loader import ModelLoader


class PipelineDependencies(BaseModel):
    """
    Injectable dependencies for the unified intelligence pipeline.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    dns_resolver: Annotated[
        DnsIntelligenceResolver | None,
        Field(default=None, description="DNS intelligence resolver"),
    ] = None
    rdap_client: Annotated[
        RdapClient | None,
        Field(default=None, description="RDAP client"),
    ] = None
    geoip_resolver: Annotated[
        GeoIpResolver | None,
        Field(default=None, description="GeoIP resolver"),
    ] = None
    reputation_service: Annotated[
        ReputationService | None,
        Field(default=None, description="Threat reputation service"),
    ] = None
    intelligence_enricher: Annotated[
        EmailIntelligenceEnricher | None,
        Field(default=None, description="High-level threat intelligence enricher"),
    ] = None
    model_loader: Annotated[
        ModelLoader | None,
        Field(default=None, description="DistilBERT model loader"),
    ] = None
    correlation_engine: Annotated[
        CorrelationEngine | None,
        Field(default=None, description="Graph and correlation engine"),
    ] = None
    campaign_clusterer: Annotated[
        CampaignClusterer | None,
        Field(default=None, description="Campaign clustering engine"),
    ] = None
    timeline_builder: Annotated[
        TimelineBuilder | None,
        Field(default=None, description="Timeline reconstruction builder"),
    ] = None
    auth_dns_resolver: Annotated[
        Any | None,
        Field(default=None, description="DNS resolver for SPF/DKIM/DMARC authentication"),
    ] = None
    historical_contexts: Annotated[
        list[AnalyzedEmailContext],
        Field(default_factory=list, description="Historical email contexts for cross-email correlation"),
    ]


def create_default_dependencies() -> PipelineDependencies:
    """
    Factory function producing standard production dependencies.

    Returns:
        Configured ``PipelineDependencies`` instance.
    """
    dns_res = DnsIntelligenceResolver()
    rdap_cl = RdapClient()
    geo_res = GeoIpResolver()
    rep_svc = ReputationService()
    enricher = EmailIntelligenceEnricher(
        dns_resolver=dns_res,
        rdap_client=rdap_cl,
        geoip_resolver=geo_res,
        reputation_service=rep_svc,
    )
    corr_engine = CorrelationEngine()
    clusterer = CampaignClusterer(correlation_engine=corr_engine)
    tl_builder = TimelineBuilder()

    return PipelineDependencies(
        dns_resolver=dns_res,
        rdap_client=rdap_cl,
        geoip_resolver=geo_res,
        reputation_service=rep_svc,
        intelligence_enricher=enricher,
        correlation_engine=corr_engine,
        campaign_clusterer=clusterer,
        timeline_builder=tl_builder,
    )
