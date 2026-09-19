"""Machine learning threat detection stage."""

from typing import Any, Dict
from backend.app.core.logging import logger
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.stages.base import BaseAnalysisStage


class MLService(BaseAnalysisStage):
    """Machine learning inference service classifying text, headers, and metadata."""

    stage_name: str = "ml"

    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute ML threat detection on ingested email."""
        try:
            from forensics.email_parser.parser import parse_email
            from ml.inference.classifier import classify_email

            parsed = parse_email(email)
            result = classify_email(parsed)

            return {
                "status": "completed",
                "stage": self.stage_name,
                "label": result.label,
                "prediction": result.label.lower(),
                "confidence": result.confidence,
                "probabilities": result.probabilities,
                "features_analyzed": True,
            }
        except Exception as exc:
            # When model weights or torch are not installed locally, return graceful status
            logger.info("ML inference unavailable: %s (falling back to neutral)", str(exc))
            return {
                "status": "not_implemented",
                "stage": self.stage_name,
                "message": f"ML model inference pending local weights: {exc}",
                "prediction": "pending",
                "label": "PENDING",
                "confidence": None,
                "features_analyzed": False,
            }

