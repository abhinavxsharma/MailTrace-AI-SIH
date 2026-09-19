"""
MAILTRACE AI — DNS Intelligence Package.

Provides typed DNS record lookups, intelligence containers, and mockable resolution.
"""

from __future__ import annotations

from intelligence.dns.models import DnsIntelligenceResult, DnsRecordResult, DnsStatus
from intelligence.dns.resolver import DEFAULT_RECORD_TYPES, DnsIntelligenceResolver

__all__ = [
    "DEFAULT_RECORD_TYPES",
    "DnsIntelligenceResult",
    "DnsRecordResult",
    "DnsIntelligenceResolver",
    "DnsStatus",
]
