"""
MAILTRACE AI — Header Forensics package.

Provides header parsing, Received hop tokenization, and deterministic header forensics.
"""

from __future__ import annotations

from forensics.headers.forensics import analyze_headers
from forensics.headers.models import HeaderForensicFinding, HeaderForensicResult
from forensics.headers.parser import parse_headers, parse_received_hop, unfold_header

__all__ = [
    "HeaderForensicFinding",
    "HeaderForensicResult",
    "analyze_headers",
    "parse_headers",
    "parse_received_hop",
    "unfold_header",
]
