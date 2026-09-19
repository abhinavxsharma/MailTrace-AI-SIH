"""
MAILTRACE AI — Input preprocessing for DistilBERT inference.

Formats ParsedEmail instances into the exact 'Subject + Body' text representation
expected by the trained dataset3_v1.0.0 model.

STRICT INVARIANT:
Does NOT inject headers, authentication results, IP addresses, GeoIP,
URLs as separate forensic features, campaign information, or risk scores.
Operates strictly in memory.
"""

from __future__ import annotations

import html as html_lib
import re
from typing import Any

from forensics.email_parser.models import ParsedEmail

# Default maximum sequence length for DistilBERT
DEFAULT_MAX_SEQUENCE_LENGTH = 512

_HTML_BREAK_REGEX = re.compile(r"(?i)<br\s*/?>|</p>|</div>|</tr>")
_HTML_TAG_REGEX = re.compile(r"<[^>]+>")
_MULTIPLE_NEWLINES_REGEX = re.compile(r"\n{3,}")
_MULTIPLE_SPACES_REGEX = re.compile(r"[ \t]+")


def strip_html_tags(raw_html: str) -> str:
    """
    Strip HTML tags and unescape entities to produce readable plain text.

    Preserves basic paragraph breaks.
    """
    if not raw_html:
        return ""

    # Replace block-closing tags and breaks with newlines
    text = _HTML_BREAK_REGEX.sub("\n", raw_html)
    # Remove remaining HTML tags
    text = _HTML_TAG_REGEX.sub(" ", text)
    # Unescape HTML entities (&amp;, &lt;, &nbsp;, etc.)
    text = html_lib.unescape(text)
    # Normalize excessive newlines and whitespace
    text = _MULTIPLE_SPACES_REGEX.sub(" ", text)
    text = _MULTIPLE_NEWLINES_REGEX.sub("\n\n", text)
    return text.strip()


def prepare_model_input(
    email_input: ParsedEmail | str | dict[str, Any],
) -> str:
    """
    Format an email into the standard 'Subject + Body' format for dataset3_v1.0.0.

    Format:
        Subject: <subject>

        Body:
        <body>

    Args:
        email_input: A ``ParsedEmail``, raw text string, or dictionary.

    Returns:
        Formatted input string ready for tokenization.
    """
    subject = ""
    body = ""

    if isinstance(email_input, ParsedEmail):
        subject = email_input.subject or ""
        # Prefer body_text; fall back to stripped body_html if text is missing
        if email_input.body_text and email_input.body_text.strip():
            body = email_input.body_text.strip()
        elif email_input.body_html and email_input.body_html.strip():
            body = strip_html_tags(email_input.body_html)
    elif isinstance(email_input, dict):
        subject = str(email_input.get("subject", "") or "")
        body_text = email_input.get("body_text") or email_input.get("body")
        body_html = email_input.get("body_html")
        if body_text and str(body_text).strip():
            body = str(body_text).strip()
        elif body_html and str(body_html).strip():
            body = strip_html_tags(str(body_html))
    elif isinstance(email_input, str):
        # Raw string input (e.g. for direct inference)
        return email_input.strip()

    subject_clean = subject.strip()
    body_clean = body.strip()

    return f"Subject: {subject_clean}\n\nBody:\n{body_clean}"
