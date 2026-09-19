"""
MAILTRACE AI — Unit tests for Graph Entity/Relationship creation and Correlation.

Tests verify:
- Graph entity creation (Email, Address, Domain, IP, URL, Message-ID, DKIM, SPF, RDAP)
- Entity and relationship deduplication
- Relationship types and evidence preservation
- Correlation rules:
  - shared sender
  - shared domain
  - shared URL
  - shared IP
  - shared Reply-To
  - shared DKIM domain
  - shared SPF domain
  - shared subject pattern
  - no correlation when indicators do not match
"""

from __future__ import annotations

import pytest

from forensics.authentication.models import (
    AlignmentResult,
    AuthenticationResult,
    DkimResult,
    DmarcResult,
    SpfResult,
)
from forensics.email_parser.models import (
    ExtractedUrl,
    ParsedAddress,
    ParsedEmail,
    ReceivedHop,
)
from graph.correlation.engine import CorrelationEngine
from graph.correlation.models import (
    AnalyzedEmailContext,
    CorrelationMatch,
    EmailGraph,
    GraphEntity,
    GraphRelationship,
)
from intelligence.models import EmailIntelligenceResult


def _make_sample_email(
    msg_id: str = "msg-1",
    from_email: str = "sender@example.com",
    from_domain: str = "example.com",
    to_email: str = "victim@target.org",
    reply_to: str | None = None,
    subject: str = "Account Notification",
    urls: list[str] | None = None,
    hops: list[str] | None = None,
) -> ParsedEmail:
    """Helper to construct a typed ParsedEmail for testing."""
    rep_addresses = []
    if reply_to:
        rep_dom = reply_to.split("@")[-1] if "@" in reply_to else ""
        rep_addresses.append(ParsedAddress(email=reply_to, domain=rep_dom))

    url_objs = []
    if urls:
        for u in urls:
            host = u.split("://")[-1].split("/")[0]
            url_objs.append(
                ExtractedUrl(original_url=u, scheme="https", host=host, path="/")
            )

    hop_objs = []
    if hops:
        for idx, h in enumerate(hops):
            hop_objs.append(
                ReceivedHop(
                    from_host=f"mail.sender.com (unknown [{h}])",
                    by_host="mx.target.org",
                    original_value=f"from mail.sender.com [{h}] by mx.target.org",
                )
            )

    return ParsedEmail(
        message_id=msg_id,
        message_id_header=f"<{msg_id}@mail.com>",
        from_address=ParsedAddress(email=from_email, domain=from_domain),
        to_addresses=[ParsedAddress(email=to_email, domain=to_email.split("@")[-1])],
        reply_to_addresses=rep_addresses,
        subject=subject,
        extracted_urls=url_objs,
        received_hops=hop_objs,
    )


def test_graph_entity_model_immutability():
    """Verify GraphEntity is frozen."""
    ent = GraphEntity(
        id="domain:example.com",
        type="domain",
        display_value="example.com",
    )
    assert ent.id == "domain:example.com"
    with pytest.raises(Exception):
        ent.display_value = "other.com"  # type: ignore


def test_build_email_graph_entities_and_relationships():
    """Verify building a complete graph with all standard entity and relationship types."""
    email = _make_sample_email(
        msg_id="msg-100",
        from_email="alert@paypal-security.com",
        from_domain="paypal-security.com",
        to_email="user@target.org",
        reply_to="drop@attacker-box.net",
        subject="Urgent Security Alert",
        urls=["https://phish.paypal-security.com/login"],
        hops=["198.51.100.25"],
    )

    auth = AuthenticationResult(
        dkim=DkimResult(status="PASS", primary_domain="paypal-security.com"),
        spf=SpfResult(status="PASS", domain="paypal-security.com"),
        dmarc=DmarcResult(status="PASS", policy="reject", policy_domain="paypal-security.com", disposition="none"),
        alignment=AlignmentResult(status="PASS", from_domain="paypal-security.com", spf_aligned=True, dkim_aligned=True),
    )

    intel = EmailIntelligenceResult(
        dns={
            "paypal-security.com": {
                "a_records": ["198.51.100.25"],
            }
        },
        rdap={
            "paypal-security.com": {
                "network_cidr": "198.51.100.0/24",
                "query_type": "domain",
            }
        },
    )

    ctx = AnalyzedEmailContext(
        parsed_email=email,
        auth_result=auth,
        intel_result=intel,
    )

    engine = CorrelationEngine()
    graph = engine.build_email_graph(ctx)

    assert isinstance(graph, EmailGraph)
    ent_ids = {e.id for e in graph.entities}
    ent_types = {e.type for e in graph.entities}

    # Verify expected entities
    assert "email:msg-100" in ent_ids
    assert "address:alert@paypal-security.com" in ent_ids
    assert "domain:paypal-security.com" in ent_ids
    assert "address:user@target.org" in ent_ids
    assert "address:drop@attacker-box.net" in ent_ids
    assert "url:https://phish.paypal-security.com/login" in ent_ids
    assert "domain:phish.paypal-security.com" in ent_ids
    assert "ip:198.51.100.25" in ent_ids
    assert "dkim_domain:paypal-security.com" in ent_ids
    assert "spf_domain:paypal-security.com" in ent_ids
    assert "rdap_network:198.51.100.0/24" in ent_ids

    # Verify relationships
    rel_types = {r.relationship_type for r in graph.relationships}
    assert "EMAIL_SENT_BY_ADDRESS" in rel_types
    assert "EMAIL_USES_DOMAIN" in rel_types
    assert "EMAIL_TARGETS_ADDRESS" in rel_types
    assert "EMAIL_REPLIES_TO" in rel_types
    assert "EMAIL_CONTAINS_URL" in rel_types
    assert "URL_HOSTS_DOMAIN" in rel_types
    assert "EMAIL_RECEIVED_FROM_IP" in rel_types
    assert "EMAIL_HAS_DKIM_DOMAIN" in rel_types
    assert "EMAIL_HAS_SPF_DOMAIN" in rel_types
    assert "DOMAIN_RESOLVES_TO_IP" in rel_types
    assert "DOMAIN_REGISTERED_TO_NETWORK" in rel_types


def test_graph_deduplication():
    """Verify entities and relationships are deduplicated when indicators appear multiple times."""
    email = _make_sample_email(
        msg_id="dup-test",
        from_email="sender@dup.org",
        from_domain="dup.org",
        urls=["https://dup.org/link1", "https://dup.org/link1"],  # duplicate URL
        hops=["198.51.100.1", "198.51.100.1"],  # duplicate hop IP
    )
    ctx = AnalyzedEmailContext(parsed_email=email)

    engine = CorrelationEngine()
    graph = engine.build_email_graph(ctx)

    # Check URL entity uniqueness
    url_nodes = [e for e in graph.entities if e.id == "url:https://dup.org/link1"]
    assert len(url_nodes) == 1

    # Check IP entity uniqueness
    ip_nodes = [e for e in graph.entities if e.id == "ip:198.51.100.1"]
    assert len(ip_nodes) == 1


def test_correlate_shared_sender():
    """Verify correlation match on exact shared sender address."""
    e1 = _make_sample_email(msg_id="e1", from_email="attacker@bad.org", subject="Invoice 1")
    e2 = _make_sample_email(msg_id="e2", from_email="attacker@bad.org", subject="Invoice 2")

    engine = CorrelationEngine()
    matches = engine.correlate_pair(
        AnalyzedEmailContext(parsed_email=e1),
        AnalyzedEmailContext(parsed_email=e2),
    )

    reasons = {m.reason for m in matches}
    assert "shared_sender" in reasons
    m = next(m for m in matches if m.reason == "shared_sender")
    assert m.shared_indicator == "attacker@bad.org"
    assert m.evidence["email_ids"] == ["e1", "e2"]


def test_correlate_shared_domain():
    """Verify correlation match on shared sender domain when local parts differ."""
    e1 = _make_sample_email(msg_id="e1", from_email="spoof1@bad.org", from_domain="bad.org")
    e2 = _make_sample_email(msg_id="e2", from_email="spoof2@bad.org", from_domain="bad.org")

    engine = CorrelationEngine()
    matches = engine.correlate_pair(
        AnalyzedEmailContext(parsed_email=e1),
        AnalyzedEmailContext(parsed_email=e2),
    )

    reasons = {m.reason for m in matches}
    assert "shared_domain" in reasons
    assert "shared_sender" not in reasons


def test_correlate_shared_url():
    """Verify correlation match on shared URL."""
    e1 = _make_sample_email(msg_id="e1", urls=["https://malware-drop.com/payload.exe"])
    e2 = _make_sample_email(msg_id="e2", urls=["https://malware-drop.com/payload.exe"])

    engine = CorrelationEngine()
    matches = engine.correlate_pair(
        AnalyzedEmailContext(parsed_email=e1),
        AnalyzedEmailContext(parsed_email=e2),
    )

    reasons = {m.reason for m in matches}
    assert "shared_url" in reasons
    m = next(m for m in matches if m.reason == "shared_url")
    assert m.shared_indicator == "https://malware-drop.com/payload.exe"


def test_correlate_shared_ip():
    """Verify correlation match on shared external Received infrastructure IP."""
    e1 = _make_sample_email(msg_id="e1", hops=["203.0.113.99"])
    e2 = _make_sample_email(msg_id="e2", hops=["203.0.113.99"])

    engine = CorrelationEngine()
    matches = engine.correlate_pair(
        AnalyzedEmailContext(parsed_email=e1),
        AnalyzedEmailContext(parsed_email=e2),
    )

    reasons = {m.reason for m in matches}
    assert "shared_ip" in reasons
    m = next(m for m in matches if m.reason == "shared_ip")
    assert m.shared_indicator == "203.0.113.99"


def test_correlate_shared_reply_to():
    """Verify correlation match on shared Reply-To address."""
    e1 = _make_sample_email(msg_id="e1", reply_to="drop@exfil.net")
    e2 = _make_sample_email(msg_id="e2", reply_to="drop@exfil.net")

    engine = CorrelationEngine()
    matches = engine.correlate_pair(
        AnalyzedEmailContext(parsed_email=e1),
        AnalyzedEmailContext(parsed_email=e2),
    )

    reasons = {m.reason for m in matches}
    assert "shared_reply_to" in reasons


def test_correlate_shared_subject_pattern():
    """Verify correlation match on normalized subject pattern."""
    e1 = _make_sample_email(msg_id="e1", subject="Urgent: Wire Transfer Request")
    e2 = _make_sample_email(msg_id="e2", subject="Re: Urgent: Wire Transfer Request")

    engine = CorrelationEngine()
    matches = engine.correlate_pair(
        AnalyzedEmailContext(parsed_email=e1),
        AnalyzedEmailContext(parsed_email=e2),
    )

    reasons = {m.reason for m in matches}
    assert "shared_subject_pattern" in reasons


def test_correlate_no_match_unrelated_emails():
    """Verify that completely unrelated emails produce no correlation matches."""
    e1 = _make_sample_email(
        msg_id="e1",
        from_email="alice@company-a.com",
        from_domain="company-a.com",
        subject="Project Alpha Meeting",
        urls=["https://company-a.com/agenda"],
        hops=["198.51.100.1"],
    )
    e2 = _make_sample_email(
        msg_id="e2",
        from_email="bob@company-b.com",
        from_domain="company-b.com",
        subject="Q3 Financial Review",
        urls=["https://company-b.com/docs"],
        hops=["198.51.100.2"],
    )

    engine = CorrelationEngine()
    matches = engine.correlate_pair(
        AnalyzedEmailContext(parsed_email=e1),
        AnalyzedEmailContext(parsed_email=e2),
    )

    assert matches == []
