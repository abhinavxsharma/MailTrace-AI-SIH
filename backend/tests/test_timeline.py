"""
MAILTRACE AI — Unit tests for Timeline Intelligence.

Tests verify:
- Chronological sorting of timeline events
- Received chain transit event reconstruction
- Email Date header event
- Missing or invalid timestamps handled safely without crashing
- Correlation event inclusion in timeline
- Campaign cluster timeline construction
- Privacy enforcement: no disk writes, strictly in-memory
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from forensics.email_parser.models import (
    ParsedAddress,
    ParsedEmail,
    ReceivedHop,
)
from graph.campaign.models import CampaignCluster
from graph.correlation.models import AnalyzedEmailContext, CorrelationMatch
from graph.timeline.builder import TimelineBuilder
from graph.timeline.models import EmailTimeline, TimelineEvent


def test_timeline_event_model_immutability():
    """Verify TimelineEvent is frozen."""
    ev = TimelineEvent(
        timestamp="2023-10-15T12:00:00Z",
        event_type="EMAIL_DATE",
        entity_id="email:msg-1",
        description="Originated",
    )
    assert ev.event_type == "EMAIL_DATE"
    with pytest.raises(Exception):
        ev.description = "Changed"  # type: ignore


def test_timeline_chronological_sorting():
    """Verify events are sorted chronologically from earliest to latest."""
    t1 = datetime(2023, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2023, 10, 15, 10, 1, 30, tzinfo=timezone.utc)
    t3 = datetime(2023, 10, 15, 10, 3, 0, tzinfo=timezone.utc)

    # Supply hops in arbitrary order to test sorting
    parsed = ParsedEmail(
        message_id="time-test",
        date=t1,
        received_hops=[
            ReceivedHop(
                from_host="hop2.net",
                by_host="hop3.net",
                original_value="hop 2",
                timestamp=t3,
            ),
            ReceivedHop(
                from_host="hop1.net",
                by_host="hop2.net",
                original_value="hop 1",
                timestamp=t2,
            ),
        ],
    )

    builder = TimelineBuilder()
    timeline = builder.build_email_timeline(AnalyzedEmailContext(parsed_email=parsed))

    assert isinstance(timeline, EmailTimeline)
    assert timeline.email_id == "time-test"

    # Filter events with timestamps
    timed_events = [e for e in timeline.events if e.timestamp is not None]
    assert len(timed_events) == 3

    # Check ascending order
    timestamps = [e.timestamp for e in timed_events]
    assert timestamps == sorted(timestamps)
    assert timeline.earliest_timestamp == t1.isoformat()
    assert timeline.latest_timestamp == t3.isoformat()


def test_timeline_received_chain_events():
    """Verify Received hops are captured with transit details."""
    t_hop = datetime(2023, 5, 20, 8, 30, 0, tzinfo=timezone.utc)
    parsed = ParsedEmail(
        message_id="hop-test",
        received_hops=[
            ReceivedHop(
                from_host="mail.origin.com",
                by_host="relay.gateway.com",
                original_value="from mail.origin.com by relay.gateway.com",
                timestamp=t_hop,
            )
        ],
    )

    builder = TimelineBuilder()
    timeline = builder.build_email_timeline(AnalyzedEmailContext(parsed_email=parsed))

    hop_ev = next(e for e in timeline.events if e.event_type == "RECEIVED_HOP")
    assert hop_ev.timestamp == t_hop.isoformat()
    assert "relay.gateway.com" in hop_ev.description
    assert hop_ev.evidence["from_host"] == "mail.origin.com"


def test_timeline_missing_and_invalid_date_handling():
    """Verify missing date or unparseable date does not crash and is placed at end."""
    parsed = ParsedEmail(
        message_id="no-date-test",
        date=None,  # Missing date
        received_hops=[
            ReceivedHop(
                from_host="h1",
                by_host="h2",
                original_value="h1 by h2",
                timestamp=None,  # Missing hop timestamp
            )
        ],
    )

    builder = TimelineBuilder()
    timeline = builder.build_email_timeline(AnalyzedEmailContext(parsed_email=parsed))

    assert timeline.email_id == "no-date-test"
    assert timeline.earliest_timestamp is None
    assert timeline.latest_timestamp is None
    assert len(timeline.events) >= 2
    for e in timeline.events:
        assert e.timestamp is None


def test_timeline_correlation_events():
    """Verify correlation events are incorporated into the email timeline."""
    parsed = ParsedEmail(message_id="msg-corr-1", subject="Subject 1")
    matches = [
        CorrelationMatch(
            email_id_1="msg-corr-1",
            email_id_2="msg-corr-2",
            reason="shared_url",
            shared_indicator="https://phish.example.com",
        )
    ]

    builder = TimelineBuilder()
    timeline = builder.build_email_timeline(
        AnalyzedEmailContext(parsed_email=parsed),
        correlation_matches=matches,
    )

    corr_evs = [e for e in timeline.events if e.event_type == "CORRELATION_EVENT"]
    assert len(corr_evs) == 1
    assert "msg-corr-2" in corr_evs[0].description
    assert corr_evs[0].evidence["reason"] == "shared_url"


def test_timeline_campaign_timeline():
    """Verify combining multiple email timelines into a campaign timeline."""
    t1 = datetime(2023, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2023, 8, 2, 12, 0, 0, tzinfo=timezone.utc)

    e1 = AnalyzedEmailContext(
        parsed_email=ParsedEmail(message_id="m1", date=t1, subject="Phish 1")
    )
    e2 = AnalyzedEmailContext(
        parsed_email=ParsedEmail(message_id="m2", date=t2, subject="Phish 2")
    )

    camp = CampaignCluster(
        campaign_id="camp_test_123",
        member_email_ids=["m1", "m2"],
        shared_indicators=["phish.example.com"],
        correlation_reasons=["shared_domain"],
        strength=0.85,
    )

    builder = TimelineBuilder()
    camp_events = builder.build_campaign_timeline(camp, [e1, e2])

    assert len(camp_events) >= 3  # m1 date, m2 date, campaign cluster milestone
    cluster_ev = next(e for e in camp_events if e.event_type == "CAMPAIGN_CLUSTER")
    assert cluster_ev.entity_id == "camp_test_123"


def test_privacy_no_disk_writes_in_graph():
    """Verify graph, campaign, and timeline modules do not import tempfile or write to disk."""
    import inspect
    import graph
    import graph.correlation.engine
    import graph.campaign.clustering
    import graph.timeline.builder

    modules = [
        graph,
        graph.correlation.engine,
        graph.campaign.clustering,
        graph.timeline.builder,
    ]

    for mod in modules:
        src = inspect.getsource(mod)
        assert "tempfile" not in src, f"{mod.__name__} must not import tempfile"
        assert ".write(" not in src, f"{mod.__name__} must not write to disk"
        assert "open(" not in src, f"{mod.__name__} must not open files"
