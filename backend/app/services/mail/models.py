"""
MAILTRACE AI — Typed domain models for the Gmail connector.

This module defines ``NormalizedEmail``, a pure Pydantic v2 model that
represents the normalized, in-memory representation of a Gmail message
after retrieval and decoding.

Architectural boundary
----------------------
``NormalizedEmail`` is the **output** of the Gmail connector (Chunk 1).
It is the **input** to the forensic analysis pipeline (Chunk 2+).

This model is intentionally decoupled from:
  - SQLAlchemy / database models
  - Gmail API response schemas
  - Any persistence layer

PRIVACY NOTE
------------
``NormalizedEmail`` never contains the raw MIME payload.  Only decoded,
normalised fields are stored here.  No .eml or raw Gmail response is
written to disk at any point.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field


class NormalizedEmail(BaseModel):
    """
    In-memory normalised representation of a Gmail message.

    All fields are populated by ``message_fetcher.fetch_and_normalize()``.
    This model is validated by Pydantic v2 on construction.

    The model is immutable by default — use ``model_copy(update={...})`` for
    derived representations.
    """

    model_config = {"frozen": True}

    # ------------------------------------------------------------------ #
    # Provider identity                                                    #
    # ------------------------------------------------------------------ #

    provider: Annotated[str, Field(description="Mail provider identifier, e.g. 'gmail'.")] = (
        "gmail"
    )

    provider_message_id: Annotated[
        str,
        Field(
            description=(
                "Opaque message ID assigned by the mail provider "
                "(Gmail message ID).  Preserved exactly as returned by the API."
            )
        ),
    ]

    thread_id: Annotated[
        str,
        Field(
            description=(
                "Thread ID from the mail provider.  "
                "Groups related messages (replies) together."
            )
        ),
    ]

    # ------------------------------------------------------------------ #
    # Envelope / routing                                                   #
    # ------------------------------------------------------------------ #

    sender: Annotated[
        str,
        Field(
            description=(
                "The 'From' header value.  May be in RFC 5322 format "
                "(e.g. 'Display Name <addr@example.com>') or bare address."
            )
        ),
    ]

    recipients: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Flattened list of recipient addresses from To, Cc, and Bcc headers."
            ),
        ),
    ]

    subject: Annotated[
        str,
        Field(
            default="",
            description="Decoded Subject header.  Empty string if absent.",
        ),
    ]

    # ------------------------------------------------------------------ #
    # Body parts (in-memory only — never persisted as raw MIME)           #
    # ------------------------------------------------------------------ #

    body_text: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Decoded text/plain body part.  None if no text/plain part "
                "exists in the message."
            ),
        ),
    ]

    body_html: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Decoded text/html body part.  None if no text/html part "
                "exists in the message."
            ),
        ),
    ]

    # ------------------------------------------------------------------ #
    # Headers                                                              #
    # ------------------------------------------------------------------ #

    headers: Annotated[
        dict[str, str],
        Field(
            default_factory=dict,
            description=(
                "Normalised message headers keyed by lowercased header name.  "
                "Where multiple values exist for the same header name, they are "
                "joined with '; '."
            ),
        ),
    ]

    # ------------------------------------------------------------------ #
    # Timestamps                                                           #
    # ------------------------------------------------------------------ #

    received_at: Annotated[
        datetime | None,
        Field(
            default=None,
            description=(
                "UTC datetime parsed from the 'Date' header.  "
                "None if the header is absent or unparseable."
            ),
        ),
    ]

    # ------------------------------------------------------------------ #
    # Optional metadata (never raw content)                               #
    # ------------------------------------------------------------------ #

    raw_size_bytes: Annotated[
        int | None,
        Field(
            default=None,
            description=(
                "Approximate size of the message in bytes as reported by "
                "the Gmail API (sizeEstimate field).  "
                "This is metadata only — the raw MIME is never stored."
            ),
        ),
    ]
