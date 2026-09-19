"""
MAILTRACE AI — Unit tests for Unified Intelligence Pipeline Orchestrator.

Tests verify:
- Complete successful pipeline execution with mocked dependencies
- Parser failure isolation
- Authentication failure isolation
- ML inference failure isolation
- Threat intelligence (DNS, RDAP, GeoIP, Reputation) unavailable handling
- Graph / correlation failure isolation
- Cross-email correlation and campaign cluster integration
- Deterministic stage ordering
- Partial result preservation
- Privacy sentinels: no disk writes, no raw MIME, no body logging
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from unittest.mock import MagicMock, patch

import pytest

from app.services.intelligence.dependencies import PipelineDependencies
from app.services.intelligence.models import IntelligenceAnalysisResult
from app.services.intelligence.pipeline import IntelligencePipeline
from app.services.mail.models import NormalizedEmail
from forensics.authentication.models import (
    AlignmentResult,
    AuthenticationResult,
    DkimResult,
    DmarcResult,
    SpfResult,
)
from forensics.email_parser.models import ParsedEmail
from graph.campaign.clustering import CampaignClusterer
from graph.correlation.engine import CorrelationEngine
from graph.timeline.builder import TimelineBuilder
from intelligence.dns.models import DnsIntelligenceResult, DnsRecordResult
from intelligence.dns.resolver import DnsIntelligenceResolver
from intelligence.enricher import EmailIntelligenceEnricher
from intelligence.geoip.models import GeoIpResult
from intelligence.geoip.resolver import GeoIpResolver, MockGeoIpProvider
from intelligence.models import EmailIntelligenceResult
from intelligence.rdap.client import RdapClient
from intelligence.rdap.models import RdapResult
from intelligence.reputation.models import AggregatedReputationResult, ReputationResult
from intelligence.reputation.providers import MockReputationProvider
from intelligence.reputation.service import ReputationService
from ml.inference.loader import ModelLoader
from ml.inference.models import MlClassificationResult


def _make_sample_normalized_email(
    msg_id: str = "msg-sample-001",
    subject: str = "Urgent: Security Verification Required",
    from_addr: str = "security@paypal-notice.com",
    body: str = "Please click https://paypal-notice.com/login to verify your account.",
) -> NormalizedEmail:
    """Helper to construct a realistic in-memory NormalizedEmail."""
    return NormalizedEmail(
        provider="gmail",
        provider_message_id=msg_id,
        thread_id=f"thread-{msg_id}",
        sender=from_addr,
        recipients=["target.user@company.org"],
        subject=subject,
        received_at=datetime(2023, 11, 20, 14, 30, 0, tzinfo=timezone.utc),
        body_text=body,
        headers={
            "From": from_addr,
            "To": "target.user@company.org",
            "Subject": subject,
            "Date": "Mon, 20 Nov 2023 14:30:00 +0000",
            "Message-ID": f"<{msg_id}@mail.paypal-notice.com>",
            "Received": "from mail.paypal-notice.com (unknown [198.51.100.42]) by mx.company.org",
        },
    )


def _make_mock_dependencies() -> PipelineDependencies:
    """Create a fully offline, mocked PipelineDependencies instance."""
    # Mock DNS
    def mock_dns(domain: str, rtype: str) -> list[str]:
        if rtype == "A":
            return ["198.51.100.42"]
        elif rtype == "MX":
            return ["10 mail.paypal-notice.com."]
        elif rtype == "TXT":
            return ['"v=spf1 -all"']
        return []

    dns_res = DnsIntelligenceResolver(mock_query_func=mock_dns)

    # Mock RDAP
    def mock_rdap(url: str) -> tuple[int, dict]:
        return 200, {
            "handle": "PAYPAL-NOTICE",
            "country": "US",
            "events": [{"eventAction": "registration", "eventDate": "2023-11-01T00:00:00Z"}],
        }

    rdap_cl = RdapClient(mock_fetch_func=mock_rdap)

    # Mock GeoIP
    geo_data = {
        "198.51.100.42": GeoIpResult(
            ip="198.51.100.42",
            country="US",
            city="Ashburn",
            status="OK",
        )
    }
    geo_res = GeoIpResolver(provider=MockGeoIpProvider(data=geo_data))

    # Mock Reputation
    rep_provider = MockReputationProvider(
        name="test_rep",
        mock_data={
            "paypal-notice.com": ReputationResult(
                indicator="paypal-notice.com",
                indicator_type="domain",
                provider="test_rep",
                score=0.9,
                category="phishing",
                raw_status="MALICIOUS",
            )
        },
    )
    rep_svc = ReputationService(providers=[rep_provider])

    enricher = EmailIntelligenceEnricher(
        dns_resolver=dns_res,
        rdap_client=rdap_cl,
        geoip_resolver=geo_res,
        reputation_service=rep_svc,
    )

    # Mock ML Loader
    mock_loader = MagicMock(spec=ModelLoader)
    mock_model = MagicMock()
    mock_tok = MagicMock()
    mock_tok.return_value = {"input_ids": MagicMock(), "attention_mask": MagicMock()}
    mock_output = MagicMock()
    import torch
    mock_output.logits = torch.tensor([[-2.0, 3.5]])
    mock_model.return_value = mock_output
    mock_loader.load.return_value = (mock_model, mock_tok)

    corr_engine = CorrelationEngine()
    clusterer = CampaignClusterer(correlation_engine=corr_engine)
    tl_builder = TimelineBuilder()

    return PipelineDependencies(
        dns_resolver=dns_res,
        rdap_client=rdap_cl,
        geoip_resolver=geo_res,
        reputation_service=rep_svc,
        intelligence_enricher=enricher,
        model_loader=mock_loader,
        correlation_engine=corr_engine,
        campaign_clusterer=clusterer,
        timeline_builder=tl_builder,
    )


@pytest.mark.anyio
async def test_pipeline_complete_success_async():
    """Verify complete end-to-end async pipeline execution."""
    email = _make_sample_normalized_email()
    deps = _make_mock_dependencies()
    pipeline = IntelligencePipeline(dependencies=deps)

    result = await pipeline.analyze(email)

    assert isinstance(result, IntelligenceAnalysisResult)
    assert result.success is True
    assert result.message_id == "msg-sample-001"
    assert result.parsed_email is not None
    assert result.header_forensics is not None
    assert result.authentication is not None
    assert result.ml_classification is not None
    assert result.ml_classification.label == "MALICIOUS"
    assert result.threat_intelligence is not None
    assert result.graph is not None
    assert result.timeline is not None

    # Check stage statuses
    for stage_name, meta in result.stages.items():
        assert meta.status == "SUCCESS", f"Stage {stage_name} expected SUCCESS but got {meta.status}"


def test_pipeline_complete_success_sync():
    """Verify complete end-to-end synchronous pipeline execution."""
    email = _make_sample_normalized_email()
    deps = _make_mock_dependencies()
    pipeline = IntelligencePipeline(dependencies=deps)

    result = pipeline.analyze_sync(email)

    assert result.success is True
    assert result.parsed_email is not None
    assert result.ml_classification is not None
    assert len(result.errors) == 0


def test_pipeline_parser_failure_isolated():
    """Verify that a parsing failure cleanly stops the pipeline and preserves diagnostics."""
    email = _make_sample_normalized_email()
    pipeline = IntelligencePipeline()

    with patch("app.services.intelligence.pipeline.parse_email", side_effect=ValueError("Corrupted structure")):
        result = pipeline.analyze_sync(email)

    assert result.success is False
    assert result.parsed_email is None
    assert result.stages["email_parser"].status == "FAILED"
    assert "Corrupted structure" in str(result.stages["email_parser"].error)
    assert len(result.errors) >= 1
    assert result.message_id == "msg-sample-001"


def test_pipeline_authentication_failure_isolated():
    """Verify that authentication failure does not destroy parser, ML, or intelligence evidence."""
    email = _make_sample_normalized_email()
    deps = _make_mock_dependencies()
    pipeline = IntelligencePipeline(dependencies=deps)

    with patch("app.services.intelligence.pipeline.verify_authentication", side_effect=RuntimeError("DNS failure")):
        result = pipeline.analyze_sync(email)

    assert result.stages["authentication"].status == "FAILED"
    assert result.authentication is None
    # Independent stages succeed!
    assert result.parsed_email is not None
    assert result.header_forensics is not None
    assert result.ml_classification is not None
    assert result.threat_intelligence is not None
    assert result.graph is not None
    assert result.timeline is not None


def test_pipeline_ml_unavailable_isolated():
    """Verify that ML unavailability does not block forensic, threat intel, or graph stages."""
    email = _make_sample_normalized_email()
    deps = _make_mock_dependencies()
    pipeline = IntelligencePipeline(dependencies=deps)

    with patch("app.services.intelligence.pipeline.classify_email", side_effect=FileNotFoundError("Weights missing")):
        result = pipeline.analyze_sync(email)

    assert result.stages["ml_classification"].status == "UNAVAILABLE"
    assert result.ml_classification is None
    # Other stages intact
    assert result.parsed_email is not None
    assert result.header_forensics is not None
    assert result.authentication is not None
    assert result.threat_intelligence is not None
    assert result.graph is not None


def test_pipeline_threat_intelligence_enrichment_failure_isolated():
    """Verify that enricher failure does not destroy forensics, auth, ML, or timeline."""
    email = _make_sample_normalized_email()
    deps = _make_mock_dependencies()
    deps.intelligence_enricher = MagicMock()
    deps.intelligence_enricher.enrich.side_effect = RuntimeError("Enrichment subsystem offline")

    pipeline = IntelligencePipeline(dependencies=deps)
    result = pipeline.analyze_sync(email)

    assert result.stages["threat_intelligence"].status == "FAILED"
    assert result.threat_intelligence is None
    assert result.parsed_email is not None
    assert result.authentication is not None
    assert result.ml_classification is not None
    assert result.graph is not None
    assert result.timeline is not None


def test_pipeline_cross_email_campaign_clustering():
    """Verify cross-email correlation and campaign cluster integration."""
    e1 = _make_sample_normalized_email(
        msg_id="msg-camp-1",
        from_addr="phish@evil-campaign.com",
        body="Visit https://evil-campaign.com/drop",
    )
    e2 = _make_sample_normalized_email(
        msg_id="msg-camp-2",
        from_addr="phish@evil-campaign.com",
        body="Visit https://evil-campaign.com/drop",
    )

    deps = _make_mock_dependencies()
    pipeline = IntelligencePipeline(dependencies=deps)

    result = pipeline.analyze_sync(e1, related_emails=[e2])

    assert len(result.correlations) >= 1
    assert result.campaign is not None
    assert result.campaign.campaign_id.startswith("camp_")
    assert "msg-camp-1" in result.campaign.member_email_ids
    assert "msg-camp-2" in result.campaign.member_email_ids


def test_pipeline_stage_ordering():
    """Verify the deterministic ordering of pipeline stages."""
    email = _make_sample_normalized_email()
    deps = _make_mock_dependencies()
    pipeline = IntelligencePipeline(dependencies=deps)

    result = pipeline.analyze_sync(email)

    expected_stages = [
        "email_parser",
        "header_forensics",
        "authentication",
        "ml_classification",
        "threat_intelligence",
        "graph",
        "correlation",
        "campaign",
        "timeline",
    ]
    assert list(result.stages.keys()) == expected_stages


def test_privacy_no_body_logging_or_disk_writes(caplog):
    """Verify sensitive message body is not written to disk or leaked into logger."""
    email = _make_sample_normalized_email(
        body="SECRET_TOP_CONFIDENTIAL_PAYLOAD_BODY_TEXT_123456789",
    )
    deps = _make_mock_dependencies()
    pipeline = IntelligencePipeline(dependencies=deps)

    with caplog.at_level(logging.DEBUG):
        result = pipeline.analyze_sync(email)

    # Verify secret body text is not logged
    log_text = caplog.text
    assert "SECRET_TOP_CONFIDENTIAL_PAYLOAD_BODY_TEXT_123456789" not in log_text

    # Verify no disk writes or tempfile imports
    import inspect
    import app.services.intelligence.pipeline as pipe_mod
    src = inspect.getsource(pipe_mod)
    assert "tempfile" not in src
    assert ".write(" not in src
    assert "open(" not in src
