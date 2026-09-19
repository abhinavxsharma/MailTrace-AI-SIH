"""
MAILTRACE AI — Unified Intelligence Pipeline Orchestrator.

Sequences end-to-end analysis for an email:
1. Email parsing (Chunk 2)
2. Header forensics (Chunk 2)
3. SPF/DKIM/DMARC authentication verification (Chunk 3)
4. DistilBERT phishing inference (Chunk 4)
5. Indicator extraction & DNS/RDAP/GeoIP/reputation enrichment (Chunk 5)
6. Graph entity and relationship construction (Chunk 6)
7. Cross-email correlation (Chunk 6)
8. Campaign clustering (Chunk 6)
9. Chronological timeline reconstruction (Chunk 6)

Ensures robust failure isolation: individual stage errors never destroy
upstream or independent evidence. Operates strictly in memory without disk writes
or sensitive body logging.
"""

from __future__ import annotations

import time
from typing import Any

from app.core.logging import get_logger
from app.services.intelligence.dependencies import (
    PipelineDependencies,
    create_default_dependencies,
)
from app.services.intelligence.models import (
    IntelligenceAnalysisResult,
    StageExecutionMetadata,
    StageStatus,
)
from app.services.mail.models import NormalizedEmail
from forensics.authentication.models import AuthenticationResult
from forensics.authentication.verifier import verify_authentication
from forensics.email_parser.models import ParsedEmail
from forensics.email_parser.parser import parse_email
from forensics.headers.forensics import analyze_headers
from forensics.headers.models import HeaderForensicResult
from graph.campaign.models import CampaignCluster
from graph.correlation.models import (
    AnalyzedEmailContext,
    CorrelationMatch,
    EmailGraph,
)
from graph.timeline.models import EmailTimeline
from intelligence.models import EmailIntelligenceResult
from ml.inference.classifier import classify_email
from ml.inference.models import MlClassificationResult

logger = get_logger(__name__)


class IntelligencePipeline:
    """
    Orchestration engine coordinating all AI and intelligence subsystems.

    Attributes:
        dependencies: Injectable dependencies for all stages.
    """

    def __init__(self, dependencies: PipelineDependencies | None = None):
        self.dependencies = dependencies or create_default_dependencies()

    async def analyze(
        self,
        email_input: NormalizedEmail | ParsedEmail,
        related_emails: list[NormalizedEmail | ParsedEmail | AnalyzedEmailContext] | None = None,
    ) -> IntelligenceAnalysisResult:
        """
        Asynchronously analyze an email through all intelligence stages.

        Args:
            email_input: NormalizedEmail from Chunk 1 or ParsedEmail from Chunk 2.
            related_emails: Optional list of related emails for cross-email correlation.

        Returns:
            ``IntelligenceAnalysisResult`` with all component evidence and stage statuses.
        """
        # Under the current implementation, all processing is CPU/memory-bound and synchronous.
        # This async wrapper provides the stable interface for FastAPI and async callers.
        return self.analyze_sync(email_input, related_emails=related_emails)

    def analyze_sync(
        self,
        email_input: NormalizedEmail | ParsedEmail,
        related_emails: list[NormalizedEmail | ParsedEmail | AnalyzedEmailContext] | None = None,
    ) -> IntelligenceAnalysisResult:
        """
        Synchronously execute the end-to-end intelligence pipeline.

        Args:
            email_input: NormalizedEmail or ParsedEmail to analyze.
            related_emails: Optional list of related emails for correlation.

        Returns:
            ``IntelligenceAnalysisResult`` containing unified evidence.
        """
        overall_start = time.monotonic()
        stages: dict[str, StageExecutionMetadata] = {}
        errors: list[str] = []

        # Extract initial identifiers safely
        if isinstance(email_input, NormalizedEmail):
            message_id = email_input.provider_message_id or "unknown_id"
            provider_message_id = email_input.provider_message_id
            thread_id = email_input.thread_id
            subject = email_input.subject
            date_str = email_input.received_at.isoformat() if email_input.received_at else None
        else:
            message_id = email_input.message_id or email_input.message_id_header or "unknown_id"
            provider_message_id = getattr(email_input, "provider_message_id", None)
            thread_id = email_input.thread_id
            subject = email_input.subject
            date_val = getattr(email_input, "date", None)
            date_str = date_val.isoformat() if date_val else None

        logger.info(f"Starting intelligence pipeline for message_id={message_id!r}")

        # ------------------------------------------------------------------ #
        # Stage 1: Email Parsing                                             #
        # ------------------------------------------------------------------ #
        parsed_email: ParsedEmail | None = None
        s1_start = time.monotonic()
        try:
            if isinstance(email_input, ParsedEmail):
                parsed_email = email_input
            else:
                parsed_email = parse_email(email_input)

            # Update identifiers from parsed object if available
            if parsed_email.subject:
                subject = parsed_email.subject
            if parsed_email.date:
                date_str = parsed_email.date.isoformat()

            stages["email_parser"] = StageExecutionMetadata(
                stage_name="email_parser",
                status="SUCCESS",
                duration_ms=self._elapsed_ms(s1_start),
            )
        except Exception as exc:
            err_msg = f"Email parser failed: {type(exc).__name__}: {exc}"
            logger.error(f"Stage email_parser failed for message_id={message_id!r}: {err_msg}")
            stages["email_parser"] = StageExecutionMetadata(
                stage_name="email_parser",
                status="FAILED",
                duration_ms=self._elapsed_ms(s1_start),
                error=err_msg,
            )
            errors.append(err_msg)
            # Cannot proceed without a parsed email
            return IntelligenceAnalysisResult(
                message_id=message_id,
                provider_message_id=provider_message_id,
                thread_id=thread_id,
                subject=subject,
                date=date_str,
                stages=stages,
                success=False,
                errors=errors,
                evidence={"duration_ms": self._elapsed_ms(overall_start)},
            )

        # ------------------------------------------------------------------ #
        # Stage 2: Header Forensics                                          #
        # ------------------------------------------------------------------ #
        header_forensics: HeaderForensicResult | None = None
        s2_start = time.monotonic()
        try:
            header_forensics = analyze_headers(parsed_email)
            stages["header_forensics"] = StageExecutionMetadata(
                stage_name="header_forensics",
                status="SUCCESS",
                duration_ms=self._elapsed_ms(s2_start),
            )
        except Exception as exc:
            err_msg = f"Header forensics failed: {type(exc).__name__}: {exc}"
            logger.error(f"Stage header_forensics failed for message_id={message_id!r}: {err_msg}")
            stages["header_forensics"] = StageExecutionMetadata(
                stage_name="header_forensics",
                status="FAILED",
                duration_ms=self._elapsed_ms(s2_start),
                error=err_msg,
            )
            errors.append(err_msg)

        # ------------------------------------------------------------------ #
        # Stage 3: SPF / DKIM / DMARC Authentication Verification           #
        # ------------------------------------------------------------------ #
        authentication: AuthenticationResult | None = None
        s3_start = time.monotonic()
        try:
            authentication = verify_authentication(
                parsed_email,
                resolver=self.dependencies.auth_dns_resolver,
            )
            stages["authentication"] = StageExecutionMetadata(
                stage_name="authentication",
                status="SUCCESS",
                duration_ms=self._elapsed_ms(s3_start),
            )
        except Exception as exc:
            err_msg = f"Authentication verification failed: {type(exc).__name__}: {exc}"
            logger.error(f"Stage authentication failed for message_id={message_id!r}: {err_msg}")
            stages["authentication"] = StageExecutionMetadata(
                stage_name="authentication",
                status="FAILED",
                duration_ms=self._elapsed_ms(s3_start),
                error=err_msg,
            )
            errors.append(err_msg)

        # ------------------------------------------------------------------ #
        # Stage 4: DistilBERT Phishing Inference                             #
        # ------------------------------------------------------------------ #
        ml_classification: MlClassificationResult | None = None
        s4_start = time.monotonic()
        try:
            ml_classification = classify_email(
                email_input=parsed_email,
                loader=self.dependencies.model_loader,
            )
            stages["ml_classification"] = StageExecutionMetadata(
                stage_name="ml_classification",
                status="SUCCESS",
                duration_ms=self._elapsed_ms(s4_start),
            )
        except Exception as exc:
            err_msg = f"ML inference failed: {type(exc).__name__}: {exc}"
            logger.error(f"Stage ml_classification failed for message_id={message_id!r}: {err_msg}")
            stages["ml_classification"] = StageExecutionMetadata(
                stage_name="ml_classification",
                status="UNAVAILABLE",
                duration_ms=self._elapsed_ms(s4_start),
                error=err_msg,
            )
            errors.append(err_msg)

        # ------------------------------------------------------------------ #
        # Stage 5: Threat Intelligence Enrichment (DNS/RDAP/GeoIP/Reputation) #
        # ------------------------------------------------------------------ #
        threat_intelligence: EmailIntelligenceResult | None = None
        s5_start = time.monotonic()
        try:
            enricher = self.dependencies.intelligence_enricher
            if enricher:
                threat_intelligence = enricher.enrich(parsed_email)
                stages["threat_intelligence"] = StageExecutionMetadata(
                    stage_name="threat_intelligence",
                    status="SUCCESS",
                    duration_ms=self._elapsed_ms(s5_start),
                )
            else:
                stages["threat_intelligence"] = StageExecutionMetadata(
                    stage_name="threat_intelligence",
                    status="SKIPPED",
                    duration_ms=0.0,
                )
        except Exception as exc:
            err_msg = f"Threat intelligence enrichment failed: {type(exc).__name__}: {exc}"
            logger.error(f"Stage threat_intelligence failed for message_id={message_id!r}: {err_msg}")
            stages["threat_intelligence"] = StageExecutionMetadata(
                stage_name="threat_intelligence",
                status="FAILED",
                duration_ms=self._elapsed_ms(s5_start),
                error=err_msg,
            )
            errors.append(err_msg)

        # Build email analysis context for downstream graph/campaign/timeline
        current_ctx = AnalyzedEmailContext(
            parsed_email=parsed_email,
            auth_result=authentication,
            ml_result=ml_classification,
            intel_result=threat_intelligence,
        )

        # ------------------------------------------------------------------ #
        # Stage 6: Entity-Relationship Graph Construction                   #
        # ------------------------------------------------------------------ #
        graph: EmailGraph | None = None
        s6_start = time.monotonic()
        try:
            corr_engine = self.dependencies.correlation_engine
            if corr_engine:
                graph = corr_engine.build_email_graph(current_ctx)
                stages["graph"] = StageExecutionMetadata(
                    stage_name="graph",
                    status="SUCCESS",
                    duration_ms=self._elapsed_ms(s6_start),
                )
            else:
                stages["graph"] = StageExecutionMetadata(stage_name="graph", status="SKIPPED")
        except Exception as exc:
            err_msg = f"Graph construction failed: {type(exc).__name__}: {exc}"
            logger.error(f"Stage graph failed for message_id={message_id!r}: {err_msg}")
            stages["graph"] = StageExecutionMetadata(
                stage_name="graph",
                status="FAILED",
                duration_ms=self._elapsed_ms(s6_start),
                error=err_msg,
            )
            errors.append(err_msg)

        # ------------------------------------------------------------------ #
        # Stage 7 & 8: Correlation and Campaign Clustering                   #
        # ------------------------------------------------------------------ #
        correlations: list[CorrelationMatch] = []
        campaign: CampaignCluster | None = None
        s7_start = time.monotonic()
        try:
            # Prepare all context objects for correlation
            all_contexts = [current_ctx]
            if related_emails:
                for rel in related_emails:
                    if isinstance(rel, AnalyzedEmailContext):
                        all_contexts.append(rel)
                    elif isinstance(rel, ParsedEmail):
                        all_contexts.append(AnalyzedEmailContext(parsed_email=rel))
                    elif isinstance(rel, NormalizedEmail):
                        try:
                            rel_parsed = parse_email(rel)
                            all_contexts.append(AnalyzedEmailContext(parsed_email=rel_parsed))
                        except Exception:
                            pass

            all_contexts.extend(self.dependencies.historical_contexts)

            corr_engine = self.dependencies.correlation_engine
            if corr_engine and len(all_contexts) > 1:
                # Correlate current email against all other contexts
                for other_ctx in all_contexts[1:]:
                    pair_matches = corr_engine.correlate_pair(current_ctx, other_ctx)
                    correlations.extend(pair_matches)

                stages["correlation"] = StageExecutionMetadata(
                    stage_name="correlation",
                    status="SUCCESS",
                    duration_ms=self._elapsed_ms(s7_start),
                )
            else:
                stages["correlation"] = StageExecutionMetadata(
                    stage_name="correlation",
                    status="SUCCESS",
                    duration_ms=self._elapsed_ms(s7_start),
                    details={"note": "Single email analysis, no cross-email correlation candidates"},
                )

            # Stage 8: Campaign Clustering
            s8_start = time.monotonic()
            clusterer = self.dependencies.campaign_clusterer
            if clusterer and correlations:
                clusters = clusterer.cluster(all_contexts, correlations=correlations)
                current_id = parsed_email.message_id or parsed_email.message_id_header
                for c in clusters:
                    if current_id in c.member_email_ids:
                        campaign = c
                        break

                stages["campaign"] = StageExecutionMetadata(
                    stage_name="campaign",
                    status="SUCCESS",
                    duration_ms=self._elapsed_ms(s8_start),
                )
            else:
                stages["campaign"] = StageExecutionMetadata(
                    stage_name="campaign",
                    status="SUCCESS",
                    duration_ms=self._elapsed_ms(s7_start),
                    details={"note": "No campaign clusters formed"},
                )

        except Exception as exc:
            err_msg = f"Correlation/campaign clustering failed: {type(exc).__name__}: {exc}"
            logger.error(f"Stage correlation/campaign failed for message_id={message_id!r}: {err_msg}")
            stages["correlation"] = StageExecutionMetadata(
                stage_name="correlation",
                status="FAILED",
                duration_ms=self._elapsed_ms(s7_start),
                error=err_msg,
            )
            errors.append(err_msg)

        # ------------------------------------------------------------------ #
        # Stage 9: Timeline Reconstruction                                   #
        # ------------------------------------------------------------------ #
        timeline: EmailTimeline | None = None
        s9_start = time.monotonic()
        try:
            tl_builder = self.dependencies.timeline_builder
            if tl_builder:
                timeline = tl_builder.build_email_timeline(current_ctx, correlation_matches=correlations)
                stages["timeline"] = StageExecutionMetadata(
                    stage_name="timeline",
                    status="SUCCESS",
                    duration_ms=self._elapsed_ms(s9_start),
                )
            else:
                stages["timeline"] = StageExecutionMetadata(stage_name="timeline", status="SKIPPED")
        except Exception as exc:
            err_msg = f"Timeline reconstruction failed: {type(exc).__name__}: {exc}"
            logger.error(f"Stage timeline failed for message_id={message_id!r}: {err_msg}")
            stages["timeline"] = StageExecutionMetadata(
                stage_name="timeline",
                status="FAILED",
                duration_ms=self._elapsed_ms(s9_start),
                error=err_msg,
            )
            errors.append(err_msg)

        total_duration = self._elapsed_ms(overall_start)
        logger.info(f"Intelligence pipeline completed for message_id={message_id!r} in {total_duration}ms")

        return IntelligenceAnalysisResult(
            message_id=message_id,
            provider_message_id=provider_message_id,
            thread_id=thread_id,
            subject=subject,
            date=date_str,
            stages=stages,
            parsed_email=parsed_email,
            header_forensics=header_forensics,
            authentication=authentication,
            ml_classification=ml_classification,
            threat_intelligence=threat_intelligence,
            graph=graph,
            correlations=correlations,
            campaign=campaign,
            timeline=timeline,
            evidence={
                "total_duration_ms": total_duration,
                "stages_count": len(stages),
                "successful_stages": sum(1 for s in stages.values() if s.status == "SUCCESS"),
            },
            success=len(errors) == 0 or (parsed_email is not None),
            errors=errors,
        )

    @staticmethod
    def _elapsed_ms(start_t: float) -> float:
        """Calculate elapsed milliseconds rounded to 2 decimal places."""
        return round((time.monotonic() - start_t) * 1000, 2)
