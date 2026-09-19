"""Deterministic risk scoring calculation stage."""

from typing import Any, Dict, Optional
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.risk.risk_engine import RiskEngine
from backend.app.services.stages.base import BaseAnalysisStage


class RiskService(BaseAnalysisStage):
    """Deterministic risk scoring service aggregating stage outputs into a 0-100 severity index."""

    stage_name: str = "risk"

    def __init__(self, risk_engine: Optional[RiskEngine] = None) -> None:
        """Initialize with an optional RiskEngine instance."""
        self.risk_engine = risk_engine or RiskEngine()

    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate categorical risk scores and level from pipeline context.

        Consumes findings from prior analysis stages without making external lookups.

        Args:
            email: Normalized email metadata.
            context: Shared pipeline context containing prior stage results.

        Returns:
            Structured risk assessment result dictionary.
        """
        evidence: Dict[str, Any] = {
            "ml": context.get("ml") or {},
            "identity": context.get("identity") or context.get("forensics", {}).get("identity", {}),
            "authentication": context.get("authentication") or {},
            "url_domain": context.get("url_domain") or context.get("intelligence", {}).get("url_domain", {}),
            "infrastructure": context.get("infrastructure") or context.get("intelligence", {}).get("infrastructure", {}),
            "campaign": context.get("campaign") or context.get("correlation", {}),
        }

        assessment = self.risk_engine.calculate_risk(evidence)

        return {
            "status": "completed",
            "stage": self.stage_name,
            "total_score": assessment["total_score"],
            "level": assessment["level"],
            "breakdown": assessment["breakdown"],
        }
