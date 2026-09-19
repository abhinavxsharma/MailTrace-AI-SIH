"""
MAILTRACE AI — Domain alignment engine for DMARC.

Implements SPF and DKIM domain alignment evaluation according to RFC 7489 section 3.1.
Supports both relaxed ('r') and strict ('s') alignment modes.
Operates strictly in memory with no external network calls.
"""

from __future__ import annotations

from typing import Any

from forensics.authentication.models import AlignmentResult

# Common two-part public suffixes for robust organizational domain derivation
_TWO_PART_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk", "me.uk",
    "co.in", "gov.in", "net.in", "org.in", "gen.in", "firm.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za",
    "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.mx", "org.mx", "gob.mx",
    "com.sg", "edu.sg", "gov.sg",
}


def get_organizational_domain(domain: str) -> str:
    """
    Extract the organizational (registrable) domain from a fully-qualified domain name.

    Examples:
        'mail.example.com' -> 'example.com'
        'sub.mail.example.co.uk' -> 'example.co.uk'
        'example.com' -> 'example.com'
        'localhost' -> 'localhost'

    Args:
        domain: Domain name string.

    Returns:
        Lowercased organizational domain.
    """
    if not domain:
        return ""

    clean = domain.strip().lower().strip(".")
    parts = clean.split(".")
    if len(parts) <= 2:
        return clean

    # Check if the last two parts constitute a known two-part TLD
    two_part_candidate = f"{parts[-2]}.{parts[-1]}"
    if two_part_candidate in _TWO_PART_TLDS:
        if len(parts) >= 3:
            return f"{parts[-3]}.{two_part_candidate}"
        return clean

    # Standard TLD: return last two labels (e.g. example.com)
    return f"{parts[-2]}.{parts[-1]}"


def check_spf_alignment(
    from_domain: str,
    return_path_domain: str | None,
    mode: str = "relaxed",
) -> bool:
    """
    Evaluate SPF domain alignment with RFC 5322 From domain.

    Args:
        from_domain: RFC 5322 From header domain.
        return_path_domain: RFC 5321 MailFrom / Return-Path domain.
        mode: Alignment mode ('relaxed'/'r' or 'strict'/'s').

    Returns:
        True if aligned, False otherwise.
    """
    if not from_domain or not return_path_domain:
        return False

    fd = from_domain.strip().lower().strip(".")
    rpd = return_path_domain.strip().lower().strip(".")

    is_strict = mode.lower() in ("strict", "s")
    if is_strict:
        return fd == rpd

    # Relaxed mode: organizational domains must match
    return get_organizational_domain(fd) == get_organizational_domain(rpd)


def check_dkim_alignment(
    from_domain: str,
    dkim_domain: str | None,
    mode: str = "relaxed",
) -> bool:
    """
    Evaluate DKIM domain alignment with RFC 5322 From domain.

    Args:
        from_domain: RFC 5322 From header domain.
        dkim_domain: DKIM signature 'd=' domain.
        mode: Alignment mode ('relaxed'/'r' or 'strict'/'s').

    Returns:
        True if aligned, False otherwise.
    """
    if not from_domain or not dkim_domain:
        return False

    fd = from_domain.strip().lower().strip(".")
    dd = dkim_domain.strip().lower().strip(".")

    is_strict = mode.lower() in ("strict", "s")
    if is_strict:
        return fd == dd

    # Relaxed mode: organizational domains must match
    return get_organizational_domain(fd) == get_organizational_domain(dd)


def evaluate_alignment(
    from_domain: str,
    return_path_domain: str | None,
    dkim_domains: list[str],
    aspf: str = "r",
    adkim: str = "r",
) -> AlignmentResult:
    """
    Perform complete DMARC alignment evaluation for both SPF and DKIM.

    Args:
        from_domain: RFC 5322 From header domain.
        return_path_domain: RFC 5321 MailFrom / Return-Path domain.
        dkim_domains: List of signing domains ('d=' tags) from valid DKIM signatures.
        aspf: SPF alignment mode ('r' or 's').
        adkim: DKIM alignment mode ('r' or 's').

    Returns:
        An ``AlignmentResult`` instance.
    """
    spf_mode = "strict" if aspf.lower() in ("s", "strict") else "relaxed"
    dkim_mode = "strict" if adkim.lower() in ("s", "strict") else "relaxed"

    spf_aligned = check_spf_alignment(from_domain, return_path_domain, mode=spf_mode)

    dkim_aligned = False
    for d_dom in dkim_domains:
        if check_dkim_alignment(from_domain, d_dom, mode=dkim_mode):
            dkim_aligned = True
            break

    evidence: dict[str, Any] = {
        "from_domain": from_domain,
        "from_org_domain": get_organizational_domain(from_domain),
        "return_path_domain": return_path_domain,
        "return_path_org_domain": (
            get_organizational_domain(return_path_domain) if return_path_domain else None
        ),
        "dkim_domains": dkim_domains,
        "aspf": aspf,
        "adkim": adkim,
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
    }

    return AlignmentResult(
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        spf_mode=spf_mode,
        dkim_mode=dkim_mode,
        from_domain=from_domain,
        spf_domain=return_path_domain,
        dkim_domains=dkim_domains,
        evidence=evidence,
    )
