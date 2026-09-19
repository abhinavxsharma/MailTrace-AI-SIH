"""
MAILTRACE AI — Email Authentication Verification package.

Provides typed in-memory verification for SPF, DKIM, DMARC, domain alignment,
and discrepancy detection against upstream Authentication-Results headers.
"""

from __future__ import annotations

from forensics.authentication.alignment import (
    check_dkim_alignment,
    check_spf_alignment,
    evaluate_alignment,
    get_organizational_domain,
)
from forensics.authentication.dkim import parse_dkim_tags, verify_dkim
from forensics.authentication.dmarc import evaluate_dmarc, parse_dmarc_tags
from forensics.authentication.models import (
    AlignmentResult,
    AuthenticationDiscrepancy,
    AuthenticationResult,
    DkimResult,
    DkimSignatureResult,
    DmarcResult,
    SpfResult,
)
from forensics.authentication.spf import (
    DefaultDnsResolver,
    DnsResolverProtocol,
    extract_connecting_ip,
    verify_spf,
)
from forensics.authentication.verifier import (
    parse_authentication_results_header,
    verify_authentication,
)

__all__ = [
    "AlignmentResult",
    "AuthenticationDiscrepancy",
    "AuthenticationResult",
    "DefaultDnsResolver",
    "DkimResult",
    "DkimSignatureResult",
    "DmarcResult",
    "DnsResolverProtocol",
    "SpfResult",
    "check_dkim_alignment",
    "check_spf_alignment",
    "evaluate_alignment",
    "evaluate_dmarc",
    "extract_connecting_ip",
    "get_organizational_domain",
    "parse_authentication_results_header",
    "parse_dkim_tags",
    "parse_dmarc_tags",
    "verify_authentication",
    "verify_dkim",
    "verify_spf",
]
