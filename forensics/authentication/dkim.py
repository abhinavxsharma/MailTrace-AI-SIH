"""
MAILTRACE AI — DKIM (DomainKeys Identified Mail) Verifier.

Validates DKIM-Signature headers, selectors, signing domains, and cryptographic
signatures per RFC 6376. Distinguishes:
- valid
- invalid
- missing
- unavailable
- malformed

Operates strictly in memory.
"""

from __future__ import annotations

import re
from typing import Any

from forensics.authentication.models import DkimResult, DkimSignatureResult
from forensics.authentication.spf import DefaultDnsResolver, DnsResolverProtocol
from forensics.email_parser.models import ParsedEmail

_DKIM_TAG_REGEX = re.compile(r"([a-zA-Z0-9]+)\s*=\s*([^;]+)")


def parse_dkim_tags(header_value: str) -> dict[str, str]:
    """
    Parse the tag=value pairs from a DKIM-Signature header.

    Whitespace is stripped from tag names and values.
    """
    tags: dict[str, str] = {}
    for match in _DKIM_TAG_REGEX.finditer(header_value):
        tag = match.group(1).strip().lower()
        val = match.group(2).strip()
        tags[tag] = val
    return tags


def _reconstruct_message_bytes(parsed_email: ParsedEmail) -> bytes:
    """
    Reconstruct the canonical in-memory RFC 822 message bytes from ParsedEmail.

    Preserves original header casing, order, and raw body.
    """
    lines: list[bytes] = []
    for h in parsed_email.headers:
        name_bytes = h.name.encode("utf-8")
        val_bytes = h.original_value.encode("utf-8")
        lines.append(b"%s: %s\r\n" % (name_bytes, val_bytes))

    lines.append(b"\r\n")

    if parsed_email.body_text:
        lines.append(parsed_email.body_text.encode("utf-8"))
    elif parsed_email.body_html:
        lines.append(parsed_email.body_html.encode("utf-8"))

    return b"".join(lines)


def verify_dkim(
    parsed_email: ParsedEmail,
    raw_message: bytes | str | None = None,
    resolver: DnsResolverProtocol | None = None,
) -> DkimResult:
    """
    Verify all DKIM signatures in a ``ParsedEmail``.

    Args:
        parsed_email: The parsed email object containing headers.
        raw_message: Optional raw RFC 822 message bytes/str for exact crypto verification.
        resolver: Pluggable DNS resolver (supporting mock DNS).

    Returns:
        Structured ``DkimResult``.
    """
    res = resolver or DefaultDnsResolver()

    # 1. Collect all DKIM-Signature headers
    dkim_headers = parsed_email.get_parsed_headers("dkim-signature")
    if not dkim_headers:
        return DkimResult(
            status="missing",
            signatures=[],
            primary_domain=None,
            error="No DKIM-Signature header present.",
            evidence={"dkim_headers_count": 0},
        )

    # 2. Prepare message bytes for dkimpy verification
    if raw_message is not None:
        message_bytes = (
            raw_message.encode("utf-8") if isinstance(raw_message, str) else raw_message
        )
    else:
        message_bytes = _reconstruct_message_bytes(parsed_email)

    sig_results: list[DkimSignatureResult] = []

    for idx, dkim_h in enumerate(dkim_headers):
        tags = parse_dkim_tags(dkim_h.original_value)
        domain = tags.get("d", "").strip().lower()
        selector = tags.get("s", "").strip()

        # Check for malformed signature (missing required tags)
        required_tags = {"d", "s", "b", "bh"}
        missing_tags = required_tags - set(tags.keys())
        if missing_tags or not domain or not selector:
            sig_results.append(
                DkimSignatureResult(
                    domain=domain or "unknown",
                    selector=selector or "unknown",
                    result="malformed",
                    signature_valid=False,
                    error=f"Malformed DKIM-Signature: missing tags {sorted(missing_tags)}",
                    evidence={"tags": tags, "raw_header": dkim_h.original_value},
                )
            )
            continue

        # Check DNS public key lookup at <selector>._domainkey.<domain>
        key_dns_name = f"{selector}._domainkey.{domain}"
        txt_records = res.get_txt_records(key_dns_name)

        # Filter for DKIM public key record
        dkim_key_records = [
            r for r in txt_records
            if "p=" in r or "v=dkim1" in r.lower()
        ]

        if not dkim_key_records:
            sig_results.append(
                DkimSignatureResult(
                    domain=domain,
                    selector=selector,
                    result="unavailable",
                    signature_valid=False,
                    error=f"DNS public key not found for '{key_dns_name}'.",
                    evidence={
                        "dns_query": key_dns_name,
                        "txt_records_found": len(txt_records),
                        "tags": tags,
                    },
                )
            )
            continue

        public_key_txt = dkim_key_records[0].strip()

        # Check if key is revoked (p= is empty)
        if "p=" in public_key_txt:
            p_val = public_key_txt.split("p=", 1)[1].split(";", 1)[0].strip()
            if not p_val:
                sig_results.append(
                    DkimSignatureResult(
                        domain=domain,
                        selector=selector,
                        result="invalid",
                        signature_valid=False,
                        error=f"DKIM public key revoked (empty p=) for '{key_dns_name}'.",
                        evidence={"public_key": public_key_txt, "tags": tags},
                    )
                )
                continue

        # Perform cryptographic verification using dkimpy
        try:
            import dkim

            def _dns_func(query_domain: str | bytes, **kwargs: Any) -> bytes | None:
                q_str = (
                    query_domain.decode("utf-8", errors="replace")
                    if isinstance(query_domain, bytes)
                    else str(query_domain)
                )
                q_clean = q_str.rstrip(".")
                records = res.get_txt_records(q_clean)
                for r in records:
                    if "p=" in r or "v=dkim1" in r.lower():
                        return r.encode("utf-8")
                return None

            dkim_obj = dkim.DKIM(message_bytes)
            is_valid = dkim_obj.verify(idx=idx, dnsfunc=_dns_func)

            if is_valid:
                sig_results.append(
                    DkimSignatureResult(
                        domain=domain,
                        selector=selector,
                        result="valid",
                        signature_valid=True,
                        error=None,
                        evidence={"tags": tags, "public_key_dns": key_dns_name},
                    )
                )
            else:
                sig_results.append(
                    DkimSignatureResult(
                        domain=domain,
                        selector=selector,
                        result="invalid",
                        signature_valid=False,
                        error="Cryptographic signature verification failed.",
                        evidence={"tags": tags, "public_key_dns": key_dns_name},
                    )
                )
        except Exception as exc:  # noqa: BLE001
            sig_results.append(
                DkimSignatureResult(
                    domain=domain,
                    selector=selector,
                    result="invalid",
                    signature_valid=False,
                    error=f"Verification exception: {exc}",
                    evidence={"tags": tags, "error": str(exc)},
                )
            )

    # 3. Determine overall DKIM status
    has_valid = any(s.result == "valid" for s in sig_results)
    if has_valid:
        primary_domain = next(s.domain for s in sig_results if s.result == "valid")
        status = "valid"
    elif any(s.result == "unavailable" for s in sig_results):
        primary_domain = sig_results[0].domain
        status = "unavailable"
    elif any(s.result == "malformed" for s in sig_results) and all(
        s.result == "malformed" for s in sig_results
    ):
        primary_domain = sig_results[0].domain
        status = "malformed"
    else:
        primary_domain = sig_results[0].domain if sig_results else None
        status = "invalid"

    return DkimResult(
        status=status,
        signatures=sig_results,
        primary_domain=primary_domain,
        error=sig_results[0].error if (not has_valid and sig_results) else None,
        evidence={
            "signatures_evaluated": len(sig_results),
            "valid_signatures_count": sum(1 for s in sig_results if s.result == "valid"),
        },
    )
