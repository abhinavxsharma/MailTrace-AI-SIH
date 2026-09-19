"""
MAILTRACE AI — Prediction utility interface.

Exposes high-level email threat classification helpers for command-line
and external caller usage using the trained dataset3_v1.0.0 DistilBERT model.
"""

from __future__ import annotations

from typing import Any

from ml.inference.classifier import classify_email
from ml.inference.models import MlClassificationResult


def predict_threat(
    subject: str,
    body: str,
    **kwargs: Any,
) -> MlClassificationResult:
    """Classify threat level for an email given subject and body."""
    return classify_email({"subject": subject, "body": body}, **kwargs)


__all__ = ["classify_email", "predict_threat", "MlClassificationResult"]
