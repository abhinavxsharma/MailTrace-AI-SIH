"""
MAILTRACE AI — Unit tests for Campaign Clustering.

Tests verify:
- Deterministic campaign grouping of correlated emails
- Separation of distinct, unrelated emails
- Multiple shared indicators and explainable strength calculation
- Deterministic campaign ID generation
- Evidence preservation across cluster members
- Multi-cluster separation within a single batch
"""

from __future__ import annotations

import pytest

from forensics.email_parser.models import (
    ExtractedUrl,
    ParsedAddress,
    ParsedEmail,
    ReceivedHop,
)
from graph.campaign.clustering import CampaignClusterer
from graph.campaign.models import CampaignCluster
from graph.correlation.engine import CorrelationEngine
from graph.correlation.models import AnalyzedEmailContext


def _make_email(
    msg_id: str,
    from_email: str,
    subject: str = "Test",
    urls: list[str] | None = None,
    hops: list[str] | None = None,
) -> AnalyzedEmailContext:
    from_domain = from_email.split("@")[-1]
    url_objs = [
        ExtractedUrl(original_url=u, scheme="https", host=u.split("://")[-1].split("/")[0], path="/")
        for u in (urls or [])
    ]
    hop_objs = [
        ReceivedHop(
            from_host=f"host [{h}]",
            by_host="mx.target.org",
            original_value=f"from host [{h}] by mx.target.org",
        )
        for h in (hops or [])
    ]
    parsed = ParsedEmail(
        message_id=msg_id,
        from_address=ParsedAddress(email=from_email, domain=from_domain),
        subject=subject,
        extracted_urls=url_objs,
        received_hops=hop_objs,
    )
    return AnalyzedEmailContext(parsed_email=parsed)


def test_campaign_cluster_model_immutability():
    """Verify CampaignCluster is frozen."""
    cluster = CampaignCluster(
        campaign_id="camp_123",
        member_email_ids=["e1", "e2"],
        shared_indicators=["example.com"],
        correlation_reasons=["shared_domain"],
        strength=0.75,
    )
    assert cluster.campaign_id == "camp_123"
    with pytest.raises(Exception):
        cluster.strength = 0.9  # type: ignore


def test_campaign_grouping_two_related_emails():
    """Verify two emails sharing sender and URL group into a campaign."""
    e1 = _make_email("e1", "phish@attacker.com", urls=["https://malicious.net/login"])
    e2 = _make_email("e2", "phish@attacker.com", urls=["https://malicious.net/login"])

    clusterer = CampaignClusterer()
    clusters = clusterer.cluster([e1, e2])

    assert len(clusters) == 1
    c = clusters[0]
    assert c.member_email_ids == ["e1", "e2"]
    assert "phish@attacker.com" in c.shared_indicators
    assert "https://malicious.net/login" in c.shared_indicators
    assert "shared_sender" in c.correlation_reasons
    assert "shared_url" in c.correlation_reasons
    assert c.strength >= 0.70
    assert c.campaign_id.startswith("camp_")


def test_campaign_distinct_unrelated_messages():
    """Verify unrelated messages do not form clusters."""
    e1 = _make_email("e1", "legit1@company1.com", urls=["https://company1.com/a"])
    e2 = _make_email("e2", "legit2@company2.com", urls=["https://company2.com/b"])
    e3 = _make_email("e3", "legit3@company3.com", urls=["https://company3.com/c"])

    clusterer = CampaignClusterer()
    clusters = clusterer.cluster([e1, e2, e3])

    assert clusters == []


def test_campaign_deterministic_ids():
    """Verify campaign IDs are strictly deterministic across runs."""
    e1 = _make_email("alpha", "threat@bad.net", urls=["https://bad.net/steal"])
    e2 = _make_email("beta", "threat@bad.net", urls=["https://bad.net/steal"])

    clusterer = CampaignClusterer()
    run1 = clusterer.cluster([e1, e2])
    run2 = clusterer.cluster([e1, e2])

    assert len(run1) == 1
    assert len(run2) == 1
    assert run1[0].campaign_id == run2[0].campaign_id


def test_campaign_multi_cluster_separation():
    """Verify distinct campaigns form independently from a single batch."""
    # Campaign A (members a1, a2)
    a1 = _make_email("a1", "gang-a@evil-a.com", urls=["https://evil-a.com/drop"])
    a2 = _make_email("a2", "gang-a@evil-a.com", urls=["https://evil-a.com/drop"])

    # Campaign B (members b1, b2)
    b1 = _make_email("b1", "gang-b@evil-b.net", urls=["https://evil-b.net/pay"])
    b2 = _make_email("b2", "gang-b@evil-b.net", urls=["https://evil-b.net/pay"])

    # Unrelated email
    c1 = _make_email("c1", "solo@neutral.org", urls=["https://neutral.org/home"])

    clusterer = CampaignClusterer()
    clusters = clusterer.cluster([a1, a2, b1, b2, c1])

    assert len(clusters) == 2
    camp_members = [set(c.member_email_ids) for c in clusters]
    assert {"a1", "a2"} in camp_members
    assert {"b1", "b2"} in camp_members
    assert not any("c1" in m for m in camp_members)


def test_campaign_evidence_preservation():
    """Verify cluster preserves full provenance and match details."""
    e1 = _make_email("e1", "scam@fake.org", hops=["198.51.100.77"])
    e2 = _make_email("e2", "scam@fake.org", hops=["198.51.100.77"])

    clusterer = CampaignClusterer()
    clusters = clusterer.cluster([e1, e2])

    assert len(clusters) == 1
    ev = clusters[0].evidence
    assert ev["member_count"] == 2
    assert ev["total_correlation_matches"] >= 2  # sender and IP
    assert len(ev["matches"]) >= 2
