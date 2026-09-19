"""
MAILTRACE AI — Indicator extraction and provenance tracking.

Extracts domains, IP addresses, and URLs from ParsedEmail objects while
preserving their exact provenance (headers, body URLs, Received hops).
Operates strictly in memory.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from forensics.email_parser.models import ParsedEmail
from intelligence.models import ExtractedIndicator, IndicatorType

_IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{3,39}")


def is_valid_ip(candidate: str) -> bool:
    """Return True if candidate string is a valid IPv4 or IPv6 address."""
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate.strip("[]"))
        return True
    except ValueError:
        return False


def extract_indicators(parsed_email: ParsedEmail) -> list[ExtractedIndicator]:
    """
    Extract deduplicated domains, IP addresses, and URLs from a ``ParsedEmail``.

    Preserves source provenance across headers, body, and Received hops.

    Args:
        parsed_email: ParsedEmail instance from Chunk 2.

    Returns:
        List of ``ExtractedIndicator`` objects.
    """
    # Key: (type, normalized_value) -> dict of data
    aggregated: dict[tuple[IndicatorType, str], dict[str, Any]] = {}

    def _add(ind_type: IndicatorType, val: str, source: str, context: dict[str, Any] | None = None) -> None:
        clean_val = val.strip().lower() if ind_type in ("domain", "ip") else val.strip()
        if not clean_val:
            return
        key = (ind_type, clean_val)
        if key not in aggregated:
            aggregated[key] = {
                "value": clean_val,
                "type": ind_type,
                "sources": [],
                "context": context or {},
            }
        if source not in aggregated[key]["sources"]:
            aggregated[key]["sources"].append(source)

    # 1. Identity header domains
    if parsed_email.from_address and parsed_email.from_address.domain:
        _add("domain", parsed_email.from_address.domain, "header:From")

    if parsed_email.sender_address and parsed_email.sender_address.domain:
        _add("domain", parsed_email.sender_address.domain, "header:Sender")

    if parsed_email.return_path and parsed_email.return_path.domain:
        _add("domain", parsed_email.return_path.domain, "header:Return-Path")

    for addr in parsed_email.to_addresses:
        if addr.domain:
            _add("domain", addr.domain, "header:To")

    for addr in parsed_email.cc_addresses:
        if addr.domain:
            _add("domain", addr.domain, "header:Cc")

    for addr in parsed_email.bcc_addresses:
        if addr.domain:
            _add("domain", addr.domain, "header:Bcc")

    for addr in parsed_email.reply_to_addresses:
        if addr.domain:
            _add("domain", addr.domain, "header:Reply-To")

    # 2. Received hops (extract IPs and host domains)
    for idx, hop in enumerate(parsed_email.received_hops):
        source_tag = f"hop:Received[{idx}]"

        # Check for explicit IP in hop attributes or raw text
        candidates = [hop.from_host, hop.by_host, hop.original_value]
        for cand in candidates:
            if not cand:
                continue
            matches = _IP_REGEX.findall(cand)
            for m in matches:
                clean_ip = m.strip("[]")
                if is_valid_ip(clean_ip):
                    _add("ip", clean_ip, source_tag, {"hop_index": idx})

        # Check from_host / by_host for domain names
        for host in (hop.from_host, hop.by_host):
            if host:
                # Remove comment / bracketed IP parts: 'mail.example.com (1.2.3.4)' -> 'mail.example.com'
                clean_host = host.split()[0].strip("()[]").lower()
                if clean_host and not is_valid_ip(clean_host) and "." in clean_host:
                    _add("domain", clean_host, source_tag, {"hop_index": idx})

    # 3. Body URLs (and their extracted host domains or IPs)
    for url_obj in parsed_email.extracted_urls:
        _add("url", url_obj.original_url, "body:URL", {"scheme": url_obj.scheme, "path": url_obj.path})

        if url_obj.host:
            host_clean = url_obj.host.strip("[]")
            if is_valid_ip(host_clean):
                _add("ip", host_clean, "body:URL", {"url": url_obj.original_url})
            elif "." in host_clean:
                _add("domain", host_clean, "body:URL", {"url": url_obj.original_url})

    results: list[ExtractedIndicator] = []
    for item in aggregated.values():
        results.append(
            ExtractedIndicator(
                value=item["value"],
                indicator_type=item["type"],
                sources=item["sources"],
                context=item["context"],
            )
        )

    return results
