"""
MAILTRACE AI — Timeline Intelligence Package.

Provides timeline event models and chronological timeline builders.
"""

from __future__ import annotations

from graph.timeline.builder import TimelineBuilder
from graph.timeline.models import EmailTimeline, TimelineEvent

__all__ = [
    "EmailTimeline",
    "TimelineBuilder",
    "TimelineEvent",
]
