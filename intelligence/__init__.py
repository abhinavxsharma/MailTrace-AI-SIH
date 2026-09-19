"""
MAILTRACE AI — Threat Intelligence and Infrastructure Enrichment Package.

Enriches extracted indicators (domains, IPs, URLs) with DNS, RDAP, GeoIP,
and threat reputation evidence. Maintains source provenance, distinguishes facts from
provider results, operates strictly in memory, and does not perform risk scoring.
"""

from __future__ import annotations

from intelligence.cache import InMemoryTtlCache
from intelligence.dns import (
    DEFAULT_RECORD_TYPES,
    DnsIntelligenceResult,
    DnsIntelligenceResolver,
    DnsRecordResult,
    DnsStatus,
)
from intelligence.enricher import EmailIntelligenceEnricher
from intelligence.extractors import extract_indicators, is_valid_ip
from intelligence.geoip import (
    GeoIpProviderProtocol,
    GeoIpResolver,
    GeoIpResult,
    GeoIpStatus,
    MaxMindGeoIpProvider,
    MissingDatabaseProvider,
    MockGeoIpProvider,
)
from intelligence.models import EmailIntelligenceResult, ExtractedIndicator, IndicatorType
from intelligence.rdap import RdapClient, RdapQueryType, RdapResult, RdapStatus
from intelligence.reputation import (
    AggregatedReputationResult,
    DnsblReputationProvider,
    MockReputationProvider,
    NotConfiguredReputationProvider,
    ReputationProviderProtocol,
    ReputationResult,
    ReputationService,
    ReputationStatus,
)

__all__ = [
    "AggregatedReputationResult",
    "DEFAULT_RECORD_TYPES",
    "DnsIntelligenceResolver",
    "DnsIntelligenceResult",
    "DnsRecordResult",
    "DnsStatus",
    "DnsblReputationProvider",
    "EmailIntelligenceEnricher",
    "EmailIntelligenceResult",
    "ExtractedIndicator",
    "GeoIpProviderProtocol",
    "GeoIpResolver",
    "GeoIpResult",
    "GeoIpStatus",
    "InMemoryTtlCache",
    "IndicatorType",
    "MaxMindGeoIpProvider",
    "MissingDatabaseProvider",
    "MockGeoIpProvider",
    "MockReputationProvider",
    "NotConfiguredReputationProvider",
    "RdapClient",
    "RdapQueryType",
    "RdapResult",
    "RdapStatus",
    "ReputationProviderProtocol",
    "ReputationResult",
    "ReputationService",
    "ReputationStatus",
    "extract_indicators",
    "is_valid_ip",
]
