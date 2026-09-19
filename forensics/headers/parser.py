"""
MAILTRACE AI — Header parser and Received hop extractor.

Provides case-insensitive header normalization, multiline unfolding,
and resilient Received-chain parsing into structured ReceivedHop objects.
No external network calls, DNS, or GeoIP lookups are performed.
"""

from __future__ import annotations

import email.utils
import re
from datetime import datetime, timezone
from typing import Any

from forensics.email_parser.models import ParsedHeader, ReceivedHop


def unfold_header(value: str) -> str:
    """
    Unfold a multiline header value per RFC 5322.

    Replaces CRLF (or LF) followed by whitespace with a single space,
    and strips leading and trailing whitespace.
    """
    if not value:
        return ""
    # RFC 5322: replace CRLF followed by WSP with a space.
    unfolded = re.sub(r"\r?\n[ \t]+", " ", value)
    # Also clean any remaining bare newlines that may be malformed folding.
    unfolded = re.sub(r"\r?\n", " ", unfolded)
    return unfolded.strip()


def parse_headers(
    raw_headers: list[tuple[str, str]] | dict[str, str] | list[dict[str, str]],
) -> list[ParsedHeader]:
    """
    Convert raw header inputs into a list of ``ParsedHeader`` objects.

    Preserves:
    - Original order of headers.
    - Repeated headers (e.g. multiple Received, duplicate identity headers).
    - Original unstripped/unfolded value alongside normalized value.

    Args:
        raw_headers: Headers as a list of (name, value) tuples, a dict,
                     or a list of {"name": ..., "value": ...} dicts.

    Returns:
        A list of ``ParsedHeader`` objects.
    """
    parsed: list[ParsedHeader] = []

    if isinstance(raw_headers, dict):
        # When passed as dict (e.g. from NormalizedEmail.headers where duplicates
        # may have been joined with '; '), we handle each key.
        for name, value in raw_headers.items():
            if not name:
                continue
            # Special case for joined 'received' headers in NormalizedEmail:
            # If multiple received hops were joined with '; from ' or similar,
            # or if it's a standard single value:
            norm = unfold_header(value)
            parsed.append(
                ParsedHeader(
                    name=name,
                    original_value=value,
                    normalized_value=norm,
                )
            )
    elif isinstance(raw_headers, list):
        for item in raw_headers:
            if isinstance(item, tuple) and len(item) == 2:
                name, value = item
            elif isinstance(item, dict):
                name = item.get("name", "")
                value = item.get("value", "")
            else:
                continue

            if not name:
                continue

            parsed.append(
                ParsedHeader(
                    name=str(name),
                    original_value=str(value),
                    normalized_value=unfold_header(str(value)),
                )
            )

    return parsed


# --------------------------------------------------------------------------- #
# Received hop parser                                                          #
# --------------------------------------------------------------------------- #

# Regex patterns for RFC 5322 Received clauses
_FROM_PATTERN = re.compile(r"\bfrom\s+([^\s;()]+(?:\s*\([^)]*\))?)", re.IGNORECASE)
_BY_PATTERN = re.compile(r"\bby\s+([^\s;()]+(?:\s*\([^)]*\))?)", re.IGNORECASE)
_WITH_PATTERN = re.compile(r"\bwith\s+([^\s;()]+)", re.IGNORECASE)
_ID_PATTERN = re.compile(r"\bid\s+([^\s;()]+)", re.IGNORECASE)
_FOR_PATTERN = re.compile(r"\bfor\s+(<[^>]+>|[^\s;()]+)", re.IGNORECASE)


def parse_received_hop(raw_header: str) -> ReceivedHop:
    """
    Parse a single RFC 5322 'Received' header into a structured ``ReceivedHop``.

    Resilient: any unparseable or absent clauses are set to None.
    Never raises an exception on malformed or unusual Received headers.

    Args:
        raw_header: The raw or unfolded text of the Received header.

    Returns:
        A ``ReceivedHop`` instance.
    """
    cleaned = unfold_header(raw_header)

    from_host: str | None = None
    by_host: str | None = None
    protocol: str | None = None
    hop_id: str | None = None
    for_recipient: str | None = None
    timestamp: datetime | None = None

    # Separate routing clauses from timestamp (timestamp follows the last ';')
    clauses_part = cleaned
    date_part: str | None = None

    if ";" in cleaned:
        # Split on the last semicolon (RFC 5322 places date after the final semicolon)
        parts = cleaned.rsplit(";", 1)
        clauses_part = parts[0].strip()
        date_part = parts[1].strip()

    # 1. Parse from_host
    from_match = _FROM_PATTERN.search(clauses_part)
    if from_match:
        from_host = from_match.group(1).strip()

    # 2. Parse by_host
    by_match = _BY_PATTERN.search(clauses_part)
    if by_match:
        by_host = by_match.group(1).strip()

    # 3. Parse protocol
    with_match = _WITH_PATTERN.search(clauses_part)
    if with_match:
        protocol = with_match.group(1).strip()

    # 4. Parse id
    id_match = _ID_PATTERN.search(clauses_part)
    if id_match:
        hop_id = id_match.group(1).strip()

    # 5. Parse for_recipient
    for_match = _FOR_PATTERN.search(clauses_part)
    if for_match:
        for_recipient = for_match.group(1).strip()

    # 6. Parse timestamp
    if date_part:
        timestamp = _parse_date_string(date_part)

    return ReceivedHop(
        original_value=raw_header,
        from_host=from_host,
        by_host=by_host,
        protocol=protocol,
        id=hop_id,
        for_recipient=for_recipient,
        timestamp=timestamp,
    )


def _parse_date_string(date_str: str) -> datetime | None:
    """Safely parse a date string into a UTC-aware datetime, or None."""
    if not date_str:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        return dt.astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        return None
