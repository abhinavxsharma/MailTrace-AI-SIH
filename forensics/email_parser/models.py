"""
MAILTRACE AI — Typed domain models for Email Parser.

This module defines Pydantic v2 models representing parsed addresses, headers,
received hops, attachments metadata, extracted URLs, and the structured parsed email.
All models are immutable (frozen) and operate strictly in memory.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field


class ParsedAddress(BaseModel):
    """
    Normalized representation of an email address.

    Attributes:
        display_name: The human-readable name (e.g. "John Doe"), or empty string.
        email: The normalized (lowercased) email address (e.g. "john@example.com").
        local_part: The portion before the '@' (e.g. "john").
        domain: The lowercased portion after the '@' (e.g. "example.com").
        original_value: The unnormalized address string as found in the header.
    """

    model_config = {"frozen": True}

    display_name: Annotated[str, Field(default="", description="Display name if present")] = ""
    email: Annotated[str, Field(default="", description="Normalized lowercased email address")] = ""
    local_part: Annotated[str, Field(default="", description="Local part of address")] = ""
    domain: Annotated[str, Field(default="", description="Domain part of address (lowercased)")] = ""
    original_value: Annotated[str, Field(default="", description="Original unparsed string")] = ""


class ParsedHeader(BaseModel):
    """
    Representation of an individual email header.

    Preserves both original casing/formatting and normalized values.
    """

    model_config = {"frozen": True}

    name: Annotated[str, Field(description="Header name (e.g. 'From', 'Received')")]
    original_value: Annotated[str, Field(description="Original unstripped header value")]
    normalized_value: Annotated[
        str, Field(description="Whitespace-normalized and unfolded header value")
    ]


class ReceivedHop(BaseModel):
    """
    Structured representation of an individual 'Received' header hop.

    Parsing is resilient and partial: any unparsed clause remains None.
    No reverse DNS, GeoIP, or reputation judgments are performed.
    """

    model_config = {"frozen": True}

    original_value: Annotated[str, Field(description="Full raw Received header text")]
    from_host: Annotated[
        str | None, Field(default=None, description="Sending host if parsed")
    ] = None
    by_host: Annotated[
        str | None, Field(default=None, description="Receiving host if parsed")
    ] = None
    protocol: Annotated[
        str | None, Field(default=None, description="Transmission protocol if parsed")
    ] = None
    id: Annotated[
        str | None, Field(default=None, description="Hop message/queue ID if parsed")
    ] = None
    for_recipient: Annotated[
        str | None, Field(default=None, description="Envelope recipient if parsed")
    ] = None
    timestamp: Annotated[
        datetime | None, Field(default=None, description="Hop timestamp in UTC if parsed")
    ] = None


class AttachmentMetadata(BaseModel):
    """
    Metadata describing an email attachment.

    PRIVACY GUARANTEE:
    Only metadata is stored. The attachment payload is never read into disk,
    never executed, and never scanned externally.
    """

    model_config = {"frozen": True}

    filename: Annotated[str, Field(default="", description="Filename of attachment")] = ""
    content_type: Annotated[
        str, Field(default="application/octet-stream", description="MIME content type")
    ] = "application/octet-stream"
    size: Annotated[
        int | None, Field(default=None, description="Size in bytes if available")
    ] = None
    content_id: Annotated[
        str | None, Field(default=None, description="Content-ID header value if present")
    ] = None
    disposition: Annotated[
        str | None,
        Field(default=None, description="Disposition type, e.g. 'attachment' or 'inline'"),
    ] = None


class ExtractedUrl(BaseModel):
    """
    Structured URL extracted from email body (text or HTML).

    No HTTP requests, DNS lookups, redirect following, or reputation checks
    are performed during extraction.
    """

    model_config = {"frozen": True}

    original_url: Annotated[str, Field(description="Exact URL string as found")]
    scheme: Annotated[str, Field(default="", description="URL scheme (http, https, etc.)")] = ""
    host: Annotated[str, Field(default="", description="Hostname/IP (lowercased)")] = ""
    port: Annotated[int | None, Field(default=None, description="Explicit port if present")] = None
    path: Annotated[str, Field(default="", description="URL path")] = ""
    query: Annotated[str, Field(default="", description="URL query string")] = ""


class ParsedEmail(BaseModel):
    """
    Comprehensive structured representation of a parsed email.

    This model serves as the architectural boundary output of Chunk 2,
    ready for header forensics and subsequent forensic analysis chunks.
    """

    model_config = {"frozen": True}

    message_id: Annotated[str, Field(description="Message identifier (provider or internal)")]
    thread_id: Annotated[str, Field(default="", description="Thread identifier if available")] = ""

    from_address: Annotated[
        ParsedAddress | None, Field(default=None, description="Parsed From address")
    ] = None
    to_addresses: Annotated[
        list[ParsedAddress], Field(default_factory=list, description="Parsed To addresses")
    ]
    cc_addresses: Annotated[
        list[ParsedAddress], Field(default_factory=list, description="Parsed Cc addresses")
    ]
    bcc_addresses: Annotated[
        list[ParsedAddress], Field(default_factory=list, description="Parsed Bcc addresses")
    ]
    reply_to_addresses: Annotated[
        list[ParsedAddress], Field(default_factory=list, description="Parsed Reply-To addresses")
    ]
    sender_address: Annotated[
        ParsedAddress | None, Field(default=None, description="Parsed Sender address")
    ] = None
    return_path: Annotated[
        ParsedAddress | None, Field(default=None, description="Parsed Return-Path address")
    ] = None

    message_id_header: Annotated[
        str | None, Field(default=None, description="RFC 5322 Message-ID header value")
    ] = None
    in_reply_to: Annotated[
        str | None, Field(default=None, description="RFC 5322 In-Reply-To header value")
    ] = None
    references: Annotated[
        list[str], Field(default_factory=list, description="RFC 5322 References header message IDs")
    ]

    date: Annotated[
        datetime | None, Field(default=None, description="Parsed Date header in UTC")
    ] = None
    subject: Annotated[str, Field(default="", description="Email subject")] = ""

    body_text: Annotated[
        str | None, Field(default=None, description="Extracted plain text body")
    ] = None
    body_html: Annotated[
        str | None, Field(default=None, description="Extracted HTML body")
    ] = None
    mime_type: Annotated[
        str | None, Field(default=None, description="Top-level MIME type")
    ] = None

    headers: Annotated[
        list[ParsedHeader],
        Field(default_factory=list, description="All parsed headers preserving order"),
    ]
    received_hops: Annotated[
        list[ReceivedHop],
        Field(default_factory=list, description="Parsed Received hops in order of appearance"),
    ]
    attachments: Annotated[
        list[AttachmentMetadata],
        Field(default_factory=list, description="Metadata for all attachments"),
    ]
    extracted_urls: Annotated[
        list[ExtractedUrl],
        Field(default_factory=list, description="Deduplicated URLs extracted from body"),
    ]

    def get_header(self, name: str) -> str | None:
        """Return the normalized_value of the first matching header (case-insensitive)."""
        target = name.lower().strip()
        for h in self.headers:
            if h.name.lower().strip() == target:
                return h.normalized_value
        return None

    def get_headers(self, name: str) -> list[str]:
        """Return a list of normalized_values for all matching headers (case-insensitive)."""
        target = name.lower().strip()
        return [
            h.normalized_value
            for h in self.headers
            if h.name.lower().strip() == target
        ]

    def get_parsed_headers(self, name: str) -> list[ParsedHeader]:
        """Return all ParsedHeader objects matching the given name (case-insensitive)."""
        target = name.lower().strip()
        return [
            h
            for h in self.headers
            if h.name.lower().strip() == target
        ]
