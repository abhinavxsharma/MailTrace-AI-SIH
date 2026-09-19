"""Deterministic risk scoring engine for MAILTRACE AI."""

from typing import Any, Dict, Optional

from backend.app.services.risk.levels import get_risk_level
from backend.app.services.risk.scoring import (
    score_ai_threat,
    score_authentication,
    score_campaign,
    score_identity,
    score_infrastructure,
    score_url_domain,
)


class RiskEngine:
    """Deterministic, local risk calculation engine.

    Aggregates multi-dimensional threat evidence into category scores
    and a unified 0-100 risk score without making external network calls.
    """

    def calculate_risk(self, evidence: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute categorical breakdown and total risk score.

        Categories and Maximum Weights:
            - AI Threat:       0 - 25
            - Identity:        0 - 20
            - Authentication:  0 - 15
            - URL / Domain:    0 - 15
            - Infrastructure:  0 - 15
            - Campaign:        0 - 10
            -------------------------
            Maximum Total:     0 - 100

        Args:
            evidence: Structured evidence dictionary containing stage findings.

        Returns:
            Dictionary with total_score, level, and breakdown.
        """
        evidence_dict = evidence if isinstance(evidence, dict) else {}

        # 1. Compute individual category scores
        ai_threat = score_ai_threat(evidence_dict.get("ml"))
        identity = score_identity(evidence_dict.get("identity"))
        authentication = score_authentication(evidence_dict.get("authentication"))
        url_domain = score_url_domain(evidence_dict.get("url_domain"))
        infrastructure = score_infrastructure(evidence_dict.get("infrastructure"))
        campaign = score_campaign(evidence_dict.get("campaign"))

        # 2. Total score is the exact sum of all 6 categories
        total_score = (
            ai_threat
            + identity
            + authentication
            + url_domain
            + infrastructure
            + campaign
        )

        # Enforce strict 0-100 bounds
        total_score = max(0, min(total_score, 100))

        # 3. Determine categorical severity level
        level = get_risk_level(total_score)

        return {
            "total_score": total_score,
            "level": level,
            "breakdown": {
                "ai_threat": ai_threat,
                "identity": identity,
                "authentication": authentication,
                "url_domain": url_domain,
                "infrastructure": infrastructure,
                "campaign": campaign,
            },
        }
