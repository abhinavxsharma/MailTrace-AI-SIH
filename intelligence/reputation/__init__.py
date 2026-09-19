"""
MAILTRACE AI — Threat Reputation Package.

Provides provider abstractions, adapters, and services for indicator reputation lookups.
"""

from __future__ import annotations

from intelligence.reputation.models import (
    AggregatedReputationResult,
    IndicatorType,
    ReputationResult,
    ReputationStatus,
)
from intelligence.reputation.providers import (
    DnsblReputationProvider,
    MockReputationProvider,
    NotConfiguredReputationProvider,
    ReputationProviderProtocol,
)
from intelligence.reputation.service import ReputationService

__all__ = [
    "AggregatedReputationResult",
    "DnsblReputationProvider",
    "IndicatorType",
    "MockReputationProvider",
    "NotConfiguredReputationProvider",
    "ReputationProviderProtocol",
    "ReputationResult",
    "ReputationService",
    "ReputationStatus",
]
