"""
MAILTRACE AI — In-memory Gmail message retrieval and normalisation.

Implements the in-memory fetch → decode → normalise pipeline:

    message_id  (Gmail message ID, opaque string)
        │
        ▼
    Gmail API   (via GmailClient.get_message, format='full')
        │
        ▼
    payload     (Google API dict, held in memory)
        │
        ▼
    decode base64url parts  (in memory only)
        │
        ▼
    walk MIME tree          (multipart supported)
        │
        ▼
    extract headers, text/plain, text/html
        │
        ▼
    NormalizedEmail         (typed Pydantic model)

PRIVACY GUARANTEE
-----------------
- No raw Gmail message (MIME, .eml, message body) is written to disk.
- No temporary files are created.
- ``tempfile`` is deliberately NOT imported.
- All data flows through memory only.
- The only persistent artefact from this module is the returned
  ``NormalizedEmail`` Pydantic object.

ARCHITECTURAL BOUNDARY
----------------------
This module ends at ``NormalizedEmail``.
Forensic analysis (header parsing, IP extraction, authentication checks,
ML inference) is NOT performed here — that is Chunk 2+.
"""

from __future__ import annotations

import base64
import email.utils
from datetime import datetime, timezone
from typing import Any

from app.core.logging import get_logger
from app.services.mail.gmail_client import GmailClient
from app.services.mail.models import NormalizedEmail

logger = get_logger(__name__)

# Gmail API response format used for all message fetches.
_FETCH_FORMAT = "full"

# MIME types we extract body text from.
_MIME_TEXT_PLAIN = "text/plain"
_MIME_TEXT_HTML = "text/html"
_MIME_MULTIPART = "multipart"


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #

def fetch_and_normalize(
    client: GmailClient,
    message_id: str,
) -> NormalizedEmail:
    """
    Fetch a Gmail message by ID and return a normalised in-memory object.

    The full Gmail API response is decoded and normalised entirely in
    memory.  Nothing is written to disk.

    Args:
        client:     An authenticated ``GmailClient`` instance.
        message_id: The Gmail message ID (opaque string from the API).

    Returns:
        A validated ``NormalizedEmail`` instance.

    Raises:
        GmailClientError:    If the Gmail API call fails.
        ValueError:          If the API response is missing required fields.
    """
    logger.info("Fetching message id=%s", message_id)

    raw_response: dict[str, Any] = client.get_message(message_id, fmt=_FETCH_FORMAT)

    return _normalize(raw_response)


# --------------------------------------------------------------------------- #
# Normalisation pipeline                                                       #
# --------------------------------------------------------------------------- #

def _normalize(raw: dict[str, Any]) -> NormalizedEmail:
    """
    Convert a Gmail API ``messages.get`` response dict into a
    ``NormalizedEmail``.

    Args:
        raw: The Gmail API response dict (format='full').

    Returns:
        A validated ``NormalizedEmail``.
    """
    provider_message_id: str = raw.get("id", "")
    thread_id: str = raw.get("threadId", "")
    size_estimate: int | None = raw.get("sizeEstimate")

    payload: dict[str, Any] = raw.get("payload", {})

    headers = _extract_headers(payload.get("headers", []))
    sender = headers.get("from", "")
    subject = headers.get("subject", "")
    recipients = _parse_recipients(headers)
    received_at = _parse_date(headers.get("date"))

    body_text, body_html = _extract_body_parts(payload)

    normalized = NormalizedEmail(
        provider="gmail",
        provider_message_id=provider_message_id,
        thread_id=thread_id,
        sender=sender,
        recipients=recipients,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        received_at=received_at,
        raw_size_bytes=size_estimate,
    )

    logger.info(
        "Normalised message id=%s thread=%s from=%r subject=%r",
        provider_message_id,
        thread_id,
        sender,
        subject,
    )

    return normalized


# --------------------------------------------------------------------------- #
# Header extraction                                                            #
# --------------------------------------------------------------------------- #

def _extract_headers(header_list: list[dict[str, str]]) -> dict[str, str]:
    """
    Convert the Gmail API header list into a normalised dict.

    Gmail returns headers as a list of ``{"name": ..., "value": ...}``
    objects.  This function:
    - Lowercases header names.
    - Joins duplicate headers with ``"; "``.

    Args:
        header_list: List of Gmail header dicts.

    Returns:
        Dict mapping lowercased header name → value string.
    """
    result: dict[str, list[str]] = {}

    for item in header_list:
        name = item.get("name", "").lower().strip()
        value = item.get("value", "").strip()
        if name:
            result.setdefault(name, []).append(value)

    return {name: "; ".join(values) for name, values in result.items()}


# --------------------------------------------------------------------------- #
# Recipient parsing                                                            #
# --------------------------------------------------------------------------- #

def _parse_recipients(headers: dict[str, str]) -> list[str]:
    """
    Extract a flat list of recipient addresses from To, Cc, and Bcc headers.

    Args:
        headers: Normalised header dict (keys lowercased).

    Returns:
        Deduplicated list of recipient address strings.
    """
    combined: list[str] = []
    for field in ("to", "cc", "bcc"):
        raw = headers.get(field, "")
        if raw:
            # email.utils.getaddresses handles comma-separated and folded headers.
            parsed = email.utils.getaddresses([raw])
            combined.extend(
                addr for _name, addr in parsed if addr
            )

    # Deduplicate preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for addr in combined:
        if addr not in seen:
            seen.add(addr)
            unique.append(addr)
    return unique


# --------------------------------------------------------------------------- #
# Date parsing                                                                 #
# --------------------------------------------------------------------------- #

def _parse_date(date_str: str | None) -> datetime | None:
    """
    Parse an RFC 2822 ``Date`` header into a UTC-aware datetime.

    Args:
        date_str: The raw Date header value, or None.

    Returns:
        A UTC-aware ``datetime``, or None if unparseable or absent.
    """
    if not date_str:
        return None

    try:
        parsed_tuple = email.utils.parsedate_to_datetime(date_str)
        # Normalise to UTC.
        return parsed_tuple.astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        logger.warning("Could not parse Date header: %r", date_str)
        return None


# --------------------------------------------------------------------------- #
# Body extraction                                                              #
# --------------------------------------------------------------------------- #

def _extract_body_parts(
    payload: dict[str, Any],
) -> tuple[str | None, str | None]:
    """
    Walk the Gmail payload MIME tree and extract text/plain and text/html
    body parts.

    All decoding is done in memory using base64url decoding.
    Nothing is written to disk.

    Args:
        payload: The ``payload`` dict from a Gmail API message (format='full').

    Returns:
        A tuple ``(body_text, body_html)`` where each is either the
        decoded string or None if that part was not present.
    """
    collector_text: list[str] = []
    collector_html: list[str] = []
    _collect_parts(payload, collector_text, collector_html)

    body_text = "".join(collector_text) or None
    body_html = "".join(collector_html) or None

    return body_text, body_html


def _collect_parts(
    part: dict[str, Any],
    text_parts: list[str],
    html_parts: list[str],
) -> None:
    """
    Recursively walk the Gmail payload MIME part tree.

    Gmail represents the message body as a tree of ``parts`` where:
    - Leaf parts have a ``body.data`` field (base64url-encoded).
    - ``multipart/*`` parts have a ``parts`` list of sub-parts.

    Args:
        part:       Current MIME part dict.
        text_parts: Accumulator for decoded text/plain content.
        html_parts: Accumulator for decoded text/html content.
    """
    mime_type: str = part.get("mimeType", "").lower()

    if mime_type.startswith(_MIME_MULTIPART):
        # Recurse into sub-parts.
        for sub_part in part.get("parts", []):
            _collect_parts(sub_part, text_parts, html_parts)
        return

    body = part.get("body", {})
    data = body.get("data", "")

    if not data:
        return

    decoded = _decode_base64url(data)
    if decoded is None:
        return

    if mime_type == _MIME_TEXT_PLAIN:
        text_parts.append(decoded)
    elif mime_type == _MIME_TEXT_HTML:
        html_parts.append(decoded)
    # Other MIME types (image/*, application/*) are ignored in this connector.


# --------------------------------------------------------------------------- #
# Base64url decoding                                                           #
# --------------------------------------------------------------------------- #

def _decode_base64url(data: str) -> str | None:
    """
    Decode a base64url-encoded string (as used in Gmail API payloads).

    Gmail uses the URL-safe variant of base64 without padding.
    This function:
    - Adds the required ``=`` padding.
    - Decodes bytes using UTF-8 with replacement for bad characters.
    - Returns None on decode failure (malformed input).

    PRIVACY: This function operates entirely in memory.
    No temporary files are created.

    Args:
        data: A base64url-encoded string from the Gmail API.

    Returns:
        The decoded string, or None if decoding fails.
    """
    if not data:
        return None

    try:
        # Gmail uses URL-safe base64 (- and _ instead of + and /).
        # Padding is stripped — we must restore it.
        padded = data + "=" * (-len(data) % 4)
        raw_bytes = base64.urlsafe_b64decode(padded)
        return raw_bytes.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        logger.warning("Failed to decode base64url payload (len=%d)", len(data))
        return None
