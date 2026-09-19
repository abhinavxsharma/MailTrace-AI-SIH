"""
MAILTRACE AI — Domain models for Timeline Intelligence.

Defines structured timeline events and chronological email histories.
All models are frozen Pydantic v2 models and operate strictly in memory.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    """
    An individual chronological event in an email or campaign timeline.

    Attributes:
        timestamp: ISO 8601 formatted timestamp string, or None if unparseable/missing.
        event_type: Category of event (EMAIL_DATE, RECEIVED_HOP, AUTH_EVALUATION, INTELLIGENCE_OBSERVATION, CORRELATION_EVENT).
        entity_id: Associated entity ID (e.g. 'email:msg-123', 'ip:1.2.3.4').
        description: Factual, human-readable description of the event.
        evidence: Provenance and raw timestamp/event metadata.
    """

    model_config = {"frozen": True}

    timestamp: Annotated[
        str | None,
        Field(default=None, description="ISO 8601 timestamp string or None"),
    ] = None
    event_type: Annotated[str, Field(description="Event classification")]
    entity_id: Annotated[str, Field(description="Associated entity ID")]
    description: Annotated[str, Field(description="Factual event description")]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Event evidence and metadata"),
    ]


class EmailTimeline(BaseModel):
    """
    Chronologically ordered timeline of events for an email.

    Attributes:
        email_id: Identifier of the email.
        events: Chronologically sorted list of TimelineEvent objects.
        earliest_timestamp: First observed timestamp in the timeline.
        latest_timestamp: Most recent observed timestamp in the timeline.
        evidence: Timeline construction metadata.
    """

    model_config = {"frozen": True}

    email_id: Annotated[str, Field(description="Email message ID")]
    events: Annotated[
        list[TimelineEvent],
        Field(default_factory=list, description="Chronologically sorted events"),
    ]
    earliest_timestamp: Annotated[
        str | None,
        Field(default=None, description="Earliest recorded timestamp"),
    ] = None
    latest_timestamp: Annotated[
        str | None,
        Field(default=None, description="Latest recorded timestamp"),
    ] = None
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Timeline metadata"),
    ]
