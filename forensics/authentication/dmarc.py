"""
MAILTRACE AI — DMARC (Domain-based Message Authentication) Evaluator.

Implements RFC 7489 DMARC policy lookup, alignment verification,
and disposition calculation. Operates strictly in memory.
"""

from __future__ import annotations

import re
from typing import Any

from forensics.authentication.alignment import (
    evaluate_alignment,
    get_organizational_domain,
)
from forensics.authentication.models import AlignmentResult, DkimResult, DmarcResult, SpfResult
from forensics.authentication.spf import DefaultDnsResolver, DnsResolverProtocol
from forensics.email_parser.models import ParsedEmail

_DMARC_TAG_REGEX = re.compile(r"([a-zA-Z0-9]+)\s*=\s*([^;]+)")


def parse_dmarc_tags(record_str: str) -> dict[str, str]:
    """Parse tag=value pairs from a DMARC TXT record."""
    tags: dict[str, str] = {}
    for match in _DMARC_TAG_REGEX.finditer(record_str):
        tag = match.group(1).strip().lower()
        val = match.group(2).strip()
        tags[tag] = val
    return tags


def evaluate_dmarc(
    parsed_email: ParsedEmail,
    spf_result: SpfResult,
    dkim_result: DkimResult,
    alignment_result: AlignmentResult | None = None,
    resolver: DnsResolverProtocol | None = None,
) -> DmarcResult:
    """
    Perform complete DMARC evaluation for an email based on SPF, DKIM,
    alignment, and DNS policy.

    Args:
        parsed_email: ParsedEmail instance.
        spf_result: Evaluated SpfResult.
        dkim_result: Evaluated DkimResult.
        alignment_result: Optional pre-evaluated AlignmentResult.
        resolver: Pluggable DNS resolver.

    Returns:
        Structured ``DmarcResult``.
    """
    res = resolver or DefaultDnsResolver()

    # 1. From domain
    from_addr = parsed_email.from_address
    from_domain = from_addr.domain if from_addr else ""
    if not from_domain:
        return DmarcResult(
            policy_domain="",
            policy="none_found",
            disposition="none",
            spf_aligned=False,
            dkim_aligned=False,
            status="NOT_EVALUATED",
            evidence={"error": "Missing RFC 5322 From header domain"},
            error="Missing From header domain",
        )

    from_domain = from_domain.strip().lower()
    org_domain = get_organizational_domain(from_domain)

    # 2. Query DMARC policy from DNS (_dmarc.<from_domain>)
    # Fallback to _dmarc.<org_domain> if from_domain is a subdomain
    policy_domain = from_domain
    dmarc_query = f"_dmarc.{from_domain}"
    txt_records = res.get_txt_records(dmarc_query)
    dmarc_records = [r for r in txt_records if r.strip().lower().startswith("v=dmarc1")]

    is_subdomain = from_domain != org_domain
    if not dmarc_records and is_subdomain:
        policy_domain = org_domain
        dmarc_query = f"_dmarc.{org_domain}"
        txt_records = res.get_txt_records(dmarc_query)
        dmarc_records = [r for r in txt_records if r.strip().lower().startswith("v=dmarc1")]

    # 3. Check for policy record presence and syntax
    if not dmarc_records:
        return DmarcResult(
            policy_domain=from_domain,
            policy="none_found",
            disposition="none",
            spf_aligned=alignment_result.spf_aligned if alignment_result else False,
            dkim_aligned=alignment_result.dkim_aligned if alignment_result else False,
            status="NONE",
            evidence={
                "from_domain": from_domain,
                "org_domain": org_domain,
                "dns_query": dmarc_query,
                "records_found": 0,
            },
        )

    if len(dmarc_records) > 1:
        return DmarcResult(
            policy_domain=policy_domain,
            policy="none_found",
            disposition="none",
            spf_aligned=False,
            dkim_aligned=False,
            status="PERMERROR",
            evidence={
                "from_domain": from_domain,
                "policy_domain": policy_domain,
                "dmarc_records": dmarc_records,
                "error": "Multiple DMARC records found",
            },
            error="Multiple DMARC records found",
        )

    raw_policy = dmarc_records[0].strip()
    tags = parse_dmarc_tags(raw_policy)

    # Validate v=DMARC1 is present
    if tags.get("v", "").lower() != "dmarc1":
        return DmarcResult(
            policy_domain=policy_domain,
            policy="none_found",
            disposition="none",
            status="PERMERROR",
            evidence={"raw_policy": raw_policy, "error": "Invalid or missing v=DMARC1 tag"},
            error="Invalid or missing v=DMARC1 tag",
        )

    # Extract policy tags
    p_tag = tags.get("p", "").lower()
    if p_tag not in ("none", "quarantine", "reject"):
        return DmarcResult(
            policy_domain=policy_domain,
            policy="none_found",
            disposition="none",
            status="PERMERROR",
            evidence={"raw_policy": raw_policy, "error": f"Invalid p= tag: {p_tag!r}"},
            error=f"Invalid p= tag: {p_tag}",
        )

    sp_tag = tags.get("sp", p_tag).lower()
    aspf = tags.get("aspf", "r").lower()
    adkim = tags.get("adkim", "r").lower()

    # Determine effective policy for this domain (p for org domain, sp for subdomain)
    effective_policy = sp_tag if is_subdomain and "sp" in tags else p_tag

    # 4. Evaluate alignment if not provided
    if alignment_result is None:
        valid_dkim_domains = [
            s.domain for s in dkim_result.signatures if s.signature_valid
        ]
        return_path_domain = (
            parsed_email.return_path.domain if parsed_email.return_path else None
        )
        alignment_result = evaluate_alignment(
            from_domain=from_domain,
            return_path_domain=return_path_domain,
            dkim_domains=valid_dkim_domains,
            aspf=aspf,
            adkim=adkim,
        )

    # 5. Determine DMARC pass/fail
    spf_pass_dmarc = (spf_result.status == "PASS") and alignment_result.spf_aligned
    dkim_pass_dmarc = (dkim_result.status == "valid") and alignment_result.dkim_aligned

    dmarc_pass = spf_pass_dmarc or dkim_pass_dmarc

    if dmarc_pass:
        status = "PASS"
        disposition = "none"
    else:
        status = "FAIL"
        disposition = effective_policy

    evidence: dict[str, Any] = {
        "from_domain": from_domain,
        "policy_domain": policy_domain,
        "raw_policy": raw_policy,
        "p": p_tag,
        "sp": sp_tag,
        "aspf": aspf,
        "adkim": adkim,
        "effective_policy": effective_policy,
        "spf_status": spf_result.status,
        "spf_aligned": alignment_result.spf_aligned,
        "spf_pass_dmarc": spf_pass_dmarc,
        "dkim_status": dkim_result.status,
        "dkim_aligned": alignment_result.dkim_aligned,
        "dkim_pass_dmarc": dkim_pass_dmarc,
        "dmarc_pass": dmarc_pass,
        "applied_disposition": disposition,
    }

    return DmarcResult(
        policy_domain=policy_domain,
        policy=effective_policy,
        disposition=disposition,
        spf_aligned=alignment_result.spf_aligned,
        dkim_aligned=alignment_result.dkim_aligned,
        status=status,
        evidence=evidence,
        error=None,
    )
