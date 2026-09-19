"""
MAILTRACE AI — Authentication Verifier Orchestrator.

Orchestrates SPF, DKIM, and DMARC verification, evaluates domain alignment,
and compares locally computed results against upstream Authentication-Results headers.
Operates strictly in memory.
"""

from __future__ import annotations

import re
from typing import Any

from forensics.authentication.alignment import evaluate_alignment
from forensics.authentication.dkim import verify_dkim
from forensics.authentication.dmarc import evaluate_dmarc
from forensics.authentication.models import (
    AuthenticationDiscrepancy,
    AuthenticationResult,
)
from forensics.authentication.spf import DefaultDnsResolver, DnsResolverProtocol, verify_spf
from forensics.email_parser.models import ParsedEmail

_AUTH_RES_METHOD_REGEX = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)",
    re.IGNORECASE,
)


def parse_authentication_results_header(header_value: str | None) -> dict[str, str]:
    """
    Extract protocol results from an RFC 7601 Authentication-Results header.

    Example:
        'mx.google.com; dkim=pass ...; spf=fail ...; dmarc=pass ...'
        -> {'dkim': 'pass', 'spf': 'fail', 'dmarc': 'pass'}
    """
    if not header_value:
        return {}

    claims: dict[str, str] = {}
    for match in _AUTH_RES_METHOD_REGEX.finditer(header_value):
        method = match.group(1).lower()
        res = match.group(2).lower()
        claims[method] = res

    return claims


def verify_authentication(
    parsed_email: ParsedEmail,
    raw_message: bytes | str | None = None,
    resolver: DnsResolverProtocol | None = None,
    connecting_ip: str | None = None,
) -> AuthenticationResult:
    """
    Run complete authentication verification for a ``ParsedEmail``.

    Pipeline:
        1. Evaluate SPF (envelope sender + connecting IP).
        2. Evaluate DKIM (DKIM-Signature headers + DNS public keys).
        3. Evaluate Domain Alignment (relaxed / strict).
        4. Evaluate DMARC (alignment + DNS policy).
        5. Compare with upstream Authentication-Results header claims.
        6. Aggregate into structured ``AuthenticationResult``.

    Args:
        parsed_email: The parsed email object.
        raw_message: Optional raw message bytes/str for exact crypto verification.
        resolver: Pluggable DNS resolver.
        connecting_ip: Explicit connecting IP (overrides Received-chain extraction).

    Returns:
        Structured ``AuthenticationResult``.
    """
    res = resolver or DefaultDnsResolver()

    # 1. SPF Verification
    spf_res = verify_spf(
        parsed_email=parsed_email,
        ip=connecting_ip,
        resolver=res,
    )

    # 2. DKIM Verification
    dkim_res = verify_dkim(
        parsed_email=parsed_email,
        raw_message=raw_message,
        resolver=res,
    )

    # 3. Alignment Evaluation
    from_domain = parsed_email.from_address.domain if parsed_email.from_address else ""
    return_path_domain = (
        parsed_email.return_path.domain if parsed_email.return_path else None
    )
    valid_dkim_domains = [
        s.domain for s in dkim_res.signatures if s.signature_valid
    ]

    alignment_res = evaluate_alignment(
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        dkim_domains=valid_dkim_domains,
        aspf="r",
        adkim="r",
    )

    # 4. DMARC Evaluation
    dmarc_res = evaluate_dmarc(
        parsed_email=parsed_email,
        spf_result=spf_res,
        dkim_result=dkim_res,
        alignment_result=alignment_res,
        resolver=res,
    )

    # 5. Upstream Authentication-Results comparison
    auth_res_header = parsed_email.get_header("authentication-results")
    header_claims = parse_authentication_results_header(auth_res_header)
    discrepancies: list[AuthenticationDiscrepancy] = []

    # Helper normalizer for comparison
    def _norm_status(val: str) -> str:
        v = val.lower().strip()
        if v in ("valid", "pass"):
            return "pass"
        if v in ("invalid", "fail"):
            return "fail"
        return v

    # Check SPF discrepancy
    if "spf" in header_claims:
        claimed_spf = header_claims["spf"]
        verified_spf = spf_res.status.lower()
        if _norm_status(claimed_spf) != _norm_status(verified_spf):
            discrepancies.append(
                AuthenticationDiscrepancy(
                    protocol="spf",
                    header_claimed_result=claimed_spf,
                    locally_verified_result=verified_spf,
                    description=(
                        f"Upstream Authentication-Results claimed SPF '{claimed_spf}', "
                        f"but local verification evaluated to '{verified_spf}'."
                    ),
                )
            )

    # Check DKIM discrepancy
    if "dkim" in header_claims:
        claimed_dkim = header_claims["dkim"]
        verified_dkim = dkim_res.status.lower()
        if _norm_status(claimed_dkim) != _norm_status(verified_dkim):
            discrepancies.append(
                AuthenticationDiscrepancy(
                    protocol="dkim",
                    header_claimed_result=claimed_dkim,
                    locally_verified_result=verified_dkim,
                    description=(
                        f"Upstream Authentication-Results claimed DKIM '{claimed_dkim}', "
                        f"but local verification evaluated to '{verified_dkim}'."
                    ),
                )
            )

    # Check DMARC discrepancy
    if "dmarc" in header_claims:
        claimed_dmarc = header_claims["dmarc"]
        verified_dmarc = dmarc_res.status.lower()
        if _norm_status(claimed_dmarc) != _norm_status(verified_dmarc):
            discrepancies.append(
                AuthenticationDiscrepancy(
                    protocol="dmarc",
                    header_claimed_result=claimed_dmarc,
                    locally_verified_result=verified_dmarc,
                    description=(
                        f"Upstream Authentication-Results claimed DMARC '{claimed_dmarc}', "
                        f"but local verification evaluated to '{verified_dmarc}'."
                    ),
                )
            )

    evidence: dict[str, Any] = {
        "spf_status": spf_res.status,
        "dkim_status": dkim_res.status,
        "dmarc_status": dmarc_res.status,
        "dmarc_policy": dmarc_res.policy,
        "dmarc_disposition": dmarc_res.disposition,
        "spf_aligned": alignment_res.spf_aligned,
        "dkim_aligned": alignment_res.dkim_aligned,
        "header_claims": header_claims,
        "discrepancies_count": len(discrepancies),
    }

    return AuthenticationResult(
        spf=spf_res,
        dkim=dkim_res,
        dmarc=dmarc_res,
        alignment=alignment_res,
        header_claims=header_claims,
        discrepancies=discrepancies,
        evidence=evidence,
    )
