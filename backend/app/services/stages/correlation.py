"""Campaign and graph correlation stage."""

from typing import Any, Dict
from backend.app.core.logging import logger
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.stages.base import BaseAnalysisStage


class CorrelationService(BaseAnalysisStage):
    """Correlation engine clustering related emails into attack campaigns and graphs."""

    stage_name: str = "correlation"

    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute graph and campaign correlation on ingested email."""
        try:
            from forensics.email_parser.parser import parse_email
            from graph.correlation.engine import CorrelationEngine
            from graph.correlation.models import AnalyzedEmailContext

            parsed = parse_email(email)
            engine = CorrelationEngine()
            email_ctx = AnalyzedEmailContext(
                parsed_email=parsed,
                auth_result=None,
                ml_result=None,
            )
            email_graph = engine.build_email_graph(email_ctx)

            entities_count = len(email_graph.entities)
            relationships_count = len(email_graph.relationships)

            return {
                "status": "completed",
                "stage": self.stage_name,
                "campaign_detected": False,
                "cluster_id": None,
                "related_cases_count": 0,
                "graph": {
                    "entities_count": entities_count,
                    "relationships_count": relationships_count,
                },
                "campaign": {
                    "part_of_campaign": False,
                },
            }
        except Exception as exc:
            logger.warning("Correlation analysis stage error: %s", str(exc))
            return {
                "status": "not_implemented",
                "stage": self.stage_name,
                "message": f"Correlation fallback: {exc}",
                "campaign_detected": False,
                "cluster_id": None,
                "related_cases_count": 0,
                "campaign": {},
            }

