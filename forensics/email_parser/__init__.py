"""
MAILTRACE AI — Email Parser package.

Provides typed parsing of NormalizedEmail instances and in-memory MIME emails
into structured ParsedEmail objects.
"""

from __future__ import annotations

from forensics.email_parser.models import (
    AttachmentMetadata,
    ExtractedUrl,
    ParsedAddress,
    ParsedEmail,
    ParsedHeader,
    ReceivedHop,
)
from forensics.email_parser.parser import (
    extract_urls,
    parse_address,
    parse_addresses,
    parse_email,
)

__all__ = [
    "AttachmentMetadata",
    "ExtractedUrl",
    "ParsedAddress",
    "ParsedEmail",
    "ParsedHeader",
    "ReceivedHop",
    "extract_urls",
    "parse_address",
    "parse_addresses",
    "parse_email",
]
