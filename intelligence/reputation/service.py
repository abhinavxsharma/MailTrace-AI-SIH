"""
MAILTRACE AI — Threat Reputation Service.

Coordinates indicator lookups across registered reputation providers.
Defaults cleanly to NOT_CONFIGURED when no providers are configured.
Maintains strict separation between observed facts, provider reports,
unavailable states, and errors.
"""

from __future__ import annotations

from typing import Sequence

from intelligence.cache import InMemoryTtlCache
from intelligence.reputation.models import (
    AggregatedReputationResult,
    IndicatorType,
    ReputationResult,
)
from intelligence.reputation.providers import (
    NotConfiguredReputationProvider,
    ReputationProviderProtocol,
)


class ReputationService:
    """
    Threat reputation orchestration service.

    Attributes:
        providers: List of configured reputation providers.
        cache: Optional InMemoryTtlCache for caching aggregated results.
    """

    def __init__(
        self,
        providers: Sequence[ReputationProviderProtocol] | None = None,
        cache: InMemoryTtlCache[AggregatedReputationResult] | None = None,
    ):
        if providers:
            self.providers = list(providers)
        else:
            self.providers = [NotConfiguredReputationProvider()]

        self.cache = cache or InMemoryTtlCache[AggregatedReputationResult](ttl_seconds=3600)

    def check(
        self,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> AggregatedReputationResult:
        """
        Check reputation for an indicator across all configured providers.

        Args:
            indicator: Indicator value (domain, IP, or URL).
            indicator_type: "domain", "ip", or "url".

        Returns:
            ``AggregatedReputationResult`` containing all provider outcomes.
        """
        clean_indicator = indicator.strip()
        cache_key = f"{indicator_type}:{clean_indicator}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        results: list[ReputationResult] = []
        for provider in self.providers:
            try:
                res = provider.check_indicator(clean_indicator, indicator_type)
                results.append(res)
            except Exception as exc:
                results.append(
                    ReputationResult(
                        indicator=clean_indicator,
                        indicator_type=indicator_type,
                        provider=getattr(provider, "name", "unknown"),
                        raw_status="ERROR",
                        evidence={"error": f"Provider execution failed: {type(exc).__name__}: {exc}"},
                    )
                )

        # Summarize aggregated status without computing a final risk score
        aggregated_status = self._derive_status(results)
        summary = self._build_summary(results, aggregated_status)

        aggregated = AggregatedReputationResult(
            indicator=clean_indicator,
            indicator_type=indicator_type,
            results=results,
            status=aggregated_status,
            summary=summary,
        )

        self.cache.set(cache_key, aggregated)
        return aggregated

    @staticmethod
    def _derive_status(results: list[ReputationResult]) -> str:
        """Derive overall category state without scoring."""
        if not results:
            return "NOT_CONFIGURED"

        statuses = {r.raw_status for r in results}
        if all(s == "NOT_CONFIGURED" for s in statuses):
            return "NOT_CONFIGURED"
        if any(s in ("LISTED", "MALICIOUS") for s in statuses):
            return "MALICIOUS"
        if any(s in ("SUSPICIOUS",) for s in statuses):
            return "SUSPICIOUS"
        if any(s in ("CLEAN", "NOT_LISTED") for s in statuses):
            return "CLEAN"
        if any(s in ("ERROR", "TIMEOUT") for s in statuses):
            return "ERROR"
        return "UNAVAILABLE"

    @staticmethod
    def _build_summary(results: list[ReputationResult], status: str) -> str:
        """Build factual summary of provider responses."""
        if status == "NOT_CONFIGURED":
            return "No reputation providers configured."

        listed = [r.provider for r in results if r.raw_status in ("LISTED", "MALICIOUS")]
        if listed:
            return f"Indicator listed by: {', '.join(listed)}"

        clean = [r.provider for r in results if r.raw_status in ("CLEAN", "NOT_LISTED")]
        if clean:
            return f"No listings found across {len(clean)} provider(s)."

        return f"Reputation status: {status}"
