"""Campaign and graph correlation stage."""

from typing import Any, Dict, List
from backend.app.core.logging import logger
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.stages.base import BaseAnalysisStage


class CorrelationService(BaseAnalysisStage):
    """Correlation engine clustering related emails into attack campaigns and graphs."""

    stage_name: str = "correlation"

    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute graph and campaign correlation on ingested email."""
        try:
            import hashlib
            from sqlalchemy import select
            from backend.app.models.case import Case
            from backend.app.models.analysis import Analysis
            from forensics.email_parser.parser import parse_email
            from graph.campaign.clustering import CampaignClusterer
            from graph.correlation.engine import CorrelationEngine
            from graph.correlation.models import AnalyzedEmailContext, CorrelationMatch
            from graph.timeline.builder import TimelineBuilder

            parsed = parse_email(email)
            engine = CorrelationEngine()
            email_ctx = AnalyzedEmailContext(
                parsed_email=parsed,
                auth_result=None,
                ml_result=None,
            )
            email_graph = engine.build_email_graph(email_ctx)

            all_matches: list[CorrelationMatch] = []
            matching_contexts: list[AnalyzedEmailContext] = []
            related_cases: list[Dict[str, Any]] = []

            # Retrieve prior cases from database to detect cross-case campaign patterns
            db = context.get("db")
            current_case_db_id = context.get("case_db_id")

            if db is not None:
                stmt = select(Case).order_by(Case.id.desc()).limit(30)
                if current_case_db_id:
                    stmt = stmt.where(Case.id != current_case_db_id)

                prior_cases = list(db.execute(stmt).scalars().all())

                for past_case in prior_cases:
                    past_headers: list[Any] = []
                    past_analysis = db.execute(
                        select(Analysis).where(Analysis.case_id == past_case.id).order_by(Analysis.id.desc())
                    ).scalars().first()

                    if past_analysis and past_analysis.forensics:
                        past_headers = past_analysis.forensics.get("headers", [])

                    # Fallback headers from case attributes
                    if not past_headers:
                        past_headers = [
                            {"name": "From", "value": past_case.sender},
                            {"name": "To", "value": past_case.recipient},
                            {"name": "Subject", "value": past_case.subject},
                        ]

                    past_email = NormalizedEmail(
                        provider=past_case.provider,
                        provider_message_id=past_case.provider_message_id,
                        thread_id=past_case.thread_id,
                        sender=past_case.sender,
                        recipient=past_case.recipient,
                        subject=past_case.subject,
                        body="",
                        headers=past_headers,
                        received_at=past_case.received_at,
                    )
                    past_parsed = parse_email(past_email)
                    past_ctx = AnalyzedEmailContext(parsed_email=past_parsed)

                    pair_matches = engine.correlate_pair(email_ctx, past_ctx)
                    if pair_matches:
                        all_matches.extend(pair_matches)
                        matching_contexts.append(past_ctx)
                        for m in pair_matches:
                            related_cases.append({
                                "case_id": past_case.case_id,
                                "provider_message_id": past_case.provider_message_id,
                                "subject": past_case.subject,
                                "reason": m.reason,
                                "shared_indicator": m.shared_indicator,
                            })

            campaign_detected = len(all_matches) > 0
            campaign_id = None
            if campaign_detected:
                clusterer = CampaignClusterer(engine)
                clusters = clusterer.cluster([email_ctx, *matching_contexts], all_matches)
                if clusters:
                    campaign_id = clusters[0].campaign_id
                else:
                    campaign_id = f"camp_{hashlib.md5(email.provider_message_id.encode()).hexdigest()[:8]}"

            # Generate chronological timeline
            timeline_builder = TimelineBuilder()
            timeline = timeline_builder.build_email_timeline(email_ctx, all_matches)

            entities_count = len(email_graph.entities)
            relationships_count = len(email_graph.relationships)

            return {
                "status": "completed",
                "stage": self.stage_name,
                "campaign_detected": campaign_detected,
                "cluster_id": campaign_id,
                "campaign_id": campaign_id,
                "related_cases_count": len(related_cases),
                "related_cases": related_cases,
                "graph": {
                    "entities_count": entities_count,
                    "relationships_count": relationships_count,
                    "entities": [e.model_dump() for e in email_graph.entities],
                    "relationships": [r.model_dump() for r in email_graph.relationships],
                },
                "campaign": {
                    "part_of_campaign": campaign_detected,
                    "potential_campaign": campaign_detected,
                    "campaign_detected": campaign_detected,
                    "cluster_id": campaign_id,
                    "campaign_id": campaign_id,
                    "shared_indicators": list({m.shared_indicator for m in all_matches}),
                    "correlation_reasons": list({m.reason for m in all_matches}),
                    "related_cases": related_cases,
                },
                "timeline": [ev.model_dump() for ev in timeline.events],
            }
        except Exception as exc:
            logger.warning("Correlation analysis stage error: %s", str(exc), exc_info=True)
            return {
                "status": "not_implemented",
                "stage": self.stage_name,
                "message": f"Correlation fallback: {exc}",
                "campaign_detected": False,
                "cluster_id": None,
                "campaign_id": None,
                "related_cases_count": 0,
                "related_cases": [],
                "campaign": {},
                "graph": {"entities_count": 0, "relationships_count": 0},
                "timeline": [],
            }
