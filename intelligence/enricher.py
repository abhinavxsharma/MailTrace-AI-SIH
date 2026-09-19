"""
MAILTRACE AI — Email Intelligence Enricher.

Orchestrates threat intelligence enrichment for parsed emails:
1. Extracts deduplicated domains, IPs, and URLs with source provenance.
2. Resolves DNS records (A, AAAA, MX, NS, TXT, CNAME) for domains.
3. Queries RDAP registration and network data.
4. Queries GeoIP location data for IPs.
5. Queries configured reputation providers for indicators.
6. Returns structured EmailIntelligenceResult.

Strictly distinguishes observed facts, provider results, unavailable states, and errors.
Does NOT calculate final 0–100 risk score (reserved for later risk fusion).
Operates strictly in memory.
"""

from __future__ import annotations

import time
from typing import Any

from forensics.email_parser.models import ParsedEmail
from intelligence.dns.resolver import DnsIntelligenceResolver
from intelligence.extractors import extract_indicators
from intelligence.geoip.resolver import GeoIpResolver
from intelligence.models import EmailIntelligenceResult, ExtractedIndicator
from intelligence.rdap.client import RdapClient
from intelligence.reputation.service import ReputationService


class EmailIntelligenceEnricher:
    """
    Threat intelligence enrichment orchestrator.

    Attributes:
        dns_resolver: Resolver for DNS intelligence.
        rdap_client: Client for RDAP lookups.
        geoip_resolver: Resolver for GeoIP lookups.
        reputation_service: Service for reputation lookups.
        max_domains: Maximum number of domains to enrich (prevents unbounded lookups).
        max_ips: Maximum number of IPs to enrich.
        max_urls: Maximum number of URLs to check.
    """

    def __init__(
        self,
        dns_resolver: DnsIntelligenceResolver | None = None,
        rdap_client: RdapClient | None = None,
        geoip_resolver: GeoIpResolver | None = None,
        reputation_service: ReputationService | None = None,
        max_domains: int = 20,
        max_ips: int = 20,
        max_urls: int = 30,
    ):
        self.dns_resolver = dns_resolver or DnsIntelligenceResolver()
        self.rdap_client = rdap_client or RdapClient()
        self.geoip_resolver = geoip_resolver or GeoIpResolver()
        self.reputation_service = reputation_service or ReputationService()
        self.max_domains = max_domains
        self.max_ips = max_ips
        self.max_urls = max_urls

    def enrich(self, parsed_email: ParsedEmail) -> EmailIntelligenceResult:
        """
        Enrich a parsed email with threat intelligence evidence.

        Args:
            parsed_email: ParsedEmail instance from Chunk 2.

        Returns:
            ``EmailIntelligenceResult`` containing all enriched evidence.
        """
        start_time = time.monotonic()

        # Step 1: Extract indicators with provenance
        indicators = extract_indicators(parsed_email)

        domains: list[ExtractedIndicator] = []
        ips: list[ExtractedIndicator] = []
        urls: list[ExtractedIndicator] = []

        for ind in indicators:
            if ind.indicator_type == "domain":
                domains.append(ind)
            elif ind.indicator_type == "ip":
                ips.append(ind)
            elif ind.indicator_type == "url":
                urls.append(ind)

        # Step 2: DNS intelligence for domains
        dns_results: dict[str, Any] = {}
        for ind in domains[: self.max_domains]:
            dns_res = self.dns_resolver.resolve_domain(ind.value)
            dns_results[ind.value] = dns_res.model_dump()

        # Step 3: RDAP intelligence for domains and IPs
        rdap_results: dict[str, Any] = {}
        for ind in domains[: self.max_domains]:
            rdap_res = self.rdap_client.lookup_domain(ind.value)
            rdap_results[ind.value] = rdap_res.model_dump()

        for ind in ips[: self.max_ips]:
            rdap_res = self.rdap_client.lookup_ip(ind.value)
            rdap_results[ind.value] = rdap_res.model_dump()

        # Step 4: GeoIP intelligence for IPs
        geoip_results: dict[str, Any] = {}
        for ind in ips[: self.max_ips]:
            geo_res = self.geoip_resolver.resolve(ind.value)
            geoip_results[ind.value] = geo_res.model_dump()

        # Step 5: Threat reputation for indicators
        reputation_results: dict[str, Any] = {}
        for ind in domains[: self.max_domains]:
            rep_res = self.reputation_service.check(ind.value, "domain")
            reputation_results[ind.value] = rep_res.model_dump()

        for ind in ips[: self.max_ips]:
            rep_res = self.reputation_service.check(ind.value, "ip")
            reputation_results[ind.value] = rep_res.model_dump()

        for ind in urls[: self.max_urls]:
            rep_res = self.reputation_service.check(ind.value, "url")
            reputation_results[ind.value] = rep_res.model_dump()

        duration_ms = round((time.monotonic() - start_time) * 1000, 2)

        evidence: dict[str, Any] = {
            "total_indicators": len(indicators),
            "total_domains": len(domains),
            "total_ips": len(ips),
            "total_urls": len(urls),
            "enrichment_duration_ms": duration_ms,
            "max_limits_applied": {
                "domains": len(domains) > self.max_domains,
                "ips": len(ips) > self.max_ips,
                "urls": len(urls) > self.max_urls,
            },
        }

        return EmailIntelligenceResult(
            indicators=indicators,
            dns=dns_results,
            rdap=rdap_results,
            geoip=geoip_results,
            reputation=reputation_results,
            evidence=evidence,
        )
