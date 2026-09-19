"""
MAILTRACE AI — Threat Reputation Providers.

Implements provider interface and adapters for indicator reputation checks.
Defaults to NOT_CONFIGURED when no provider is set up.
Supports dependency injection for tests and DNSBL provider implementations.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Callable, Protocol

from intelligence.reputation.models import IndicatorType, ReputationResult


class ReputationProviderProtocol(Protocol):
    """Protocol defining a threat reputation provider."""

    @property
    def name(self) -> str:
        """Provider identifier."""
        ...

    def is_configured(self) -> bool:
        """Return True if the provider has necessary credentials/configuration."""
        ...

    def check_indicator(self, indicator: str, indicator_type: IndicatorType) -> ReputationResult:
        """
        Query provider for indicator reputation.

        Args:
            indicator: The indicator string (domain, IP, URL).
            indicator_type: "domain", "ip", or "url".

        Returns:
            ``ReputationResult`` containing provider response.
        """
        ...


class NotConfiguredReputationProvider:
    """
    Default provider when no threat reputation service is configured.
    Ensures safe, non-fabricated, and predictable behavior without external network calls.
    """

    @property
    def name(self) -> str:
        return "none"

    def is_configured(self) -> bool:
        return False

    def check_indicator(self, indicator: str, indicator_type: IndicatorType) -> ReputationResult:
        return ReputationResult(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self.name,
            score=None,
            category=None,
            confidence=None,
            raw_status="NOT_CONFIGURED",
            evidence={"reason": "No reputation provider is configured"},
        )


class MockReputationProvider:
    """Mock provider for unit tests and offline testing."""

    def __init__(
        self,
        name: str = "mock_provider",
        configured: bool = True,
        mock_data: dict[str, ReputationResult] | None = None,
        mock_func: Callable[[str, IndicatorType], ReputationResult] | None = None,
    ):
        self._name = name
        self._configured = configured
        self._mock_data = mock_data or {}
        self._mock_func = mock_func

    @property
    def name(self) -> str:
        return self._name

    def is_configured(self) -> bool:
        return self._configured

    def check_indicator(self, indicator: str, indicator_type: IndicatorType) -> ReputationResult:
        if not self._configured:
            return ReputationResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self._name,
                raw_status="NOT_CONFIGURED",
                evidence={"reason": "Mock provider configured as disabled"},
            )

        if self._mock_func:
            return self._mock_func(indicator, indicator_type)

        if indicator in self._mock_data:
            return self._mock_data[indicator]

        return ReputationResult(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self._name,
            raw_status="NOT_FOUND",
            evidence={"reason": "Indicator not in mock dataset"},
        )


class DnsblReputationProvider:
    """
    DNS-based Blackhole List (DNSBL) reputation provider adapter.
    Supports querying IP and domain blacklists via DNS resolution.
    Accepts an injected mock query function to ensure 100% offline unit tests.
    """

    def __init__(
        self,
        zone: str,
        name: str | None = None,
        dns_query_func: Callable[[str, str], list[str]] | None = None,
        timeout: float = 2.0,
    ):
        self.zone = zone.strip().rstrip(".")
        self._name = name or f"dnsbl_{self.zone}"
        self.dns_query_func = dns_query_func
        self.timeout = timeout

    @property
    def name(self) -> str:
        return self._name

    def is_configured(self) -> bool:
        return bool(self.zone)

    def check_indicator(self, indicator: str, indicator_type: IndicatorType) -> ReputationResult:
        if indicator_type == "url":
            # DNSBL does not support raw URLs directly without domain extraction
            return ReputationResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                raw_status="UNSUPPORTED_TYPE",
                evidence={"reason": "DNSBL queries require domain or IP"},
            )

        # Build DNSBL query hostname
        query_host = self._build_query_host(indicator, indicator_type)
        if not query_host:
            return ReputationResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                raw_status="MALFORMED",
                evidence={"reason": "Failed to construct DNSBL query host"},
            )

        # Query DNS
        try:
            if self.dns_query_func is not None:
                records = self.dns_query_func(query_host, "A")
            else:
                import dns.resolver

                resolver = dns.resolver.Resolver()
                resolver.lifetime = self.timeout
                resolver.timeout = self.timeout
                answer = resolver.resolve(query_host, "A")
                records = [rdata.to_text() for rdata in answer]

            if records:
                # An A record response from a DNSBL means the indicator is listed
                return ReputationResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider=self.name,
                    score=1.0,
                    category="listed",
                    confidence=0.9,
                    raw_status="LISTED",
                    evidence={"response_records": records, "query_host": query_host},
                )
            else:
                return ReputationResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider=self.name,
                    score=0.0,
                    category="clean",
                    raw_status="NOT_LISTED",
                    evidence={"query_host": query_host},
                )

        except Exception as exc:
            err_name = type(exc).__name__
            if "NXDOMAIN" in err_name:
                # NXDOMAIN from DNSBL means NOT listed (clean)
                return ReputationResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider=self.name,
                    score=0.0,
                    category="clean",
                    raw_status="CLEAN",
                    evidence={"reason": "NXDOMAIN (not listed in DNSBL)", "query_host": query_host},
                )
            elif "Timeout" in err_name:
                return ReputationResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider=self.name,
                    raw_status="TIMEOUT",
                    evidence={"error": f"DNSBL lookup timed out: {exc}", "query_host": query_host},
                )
            else:
                return ReputationResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider=self.name,
                    raw_status="ERROR",
                    evidence={"error": f"DNSBL error: {err_name}: {exc}", "query_host": query_host},
                )

    def _build_query_host(self, indicator: str, indicator_type: IndicatorType) -> str | None:
        """Construct the reversed IP or domain lookup string for DNSBL."""
        if indicator_type == "ip":
            try:
                ip_obj = ipaddress.ip_address(indicator.strip())
                if ip_obj.version == 4:
                    octets = indicator.strip().split(".")
                    reversed_ip = ".".join(reversed(octets))
                    return f"{reversed_ip}.{self.zone}"
                elif ip_obj.version == 6:
                    # IPv6 reverse nibble format
                    exploded = ip_obj.exploded.replace(":", "")
                    reversed_nibbles = ".".join(reversed(list(exploded)))
                    return f"{reversed_nibbles}.{self.zone}"
            except ValueError:
                return None
        elif indicator_type == "domain":
            clean = indicator.strip().lower().rstrip(".")
            return f"{clean}.{self.zone}"
        return None
