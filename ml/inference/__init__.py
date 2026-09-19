"""
MAILTRACE AI — ML Inference package for DistilBERT (dataset3_v1.0.0).

Provides deterministic sequence classification on email content (Subject + Body).
"""

from __future__ import annotations

from ml.inference.classifier import classify_email
from ml.inference.loader import ModelLoader, get_default_loader
from ml.inference.models import (
    MlClassificationResult,
    MlInferenceError,
    ModelInputError,
    ModelNotFoundError,
)
from ml.inference.preprocessing import (
    DEFAULT_MAX_SEQUENCE_LENGTH,
    prepare_model_input,
    strip_html_tags,
)

__all__ = [
    "DEFAULT_MAX_SEQUENCE_LENGTH",
    "MlClassificationResult",
    "MlInferenceError",
    "ModelInputError",
    "ModelLoader",
    "ModelNotFoundError",
    "classify_email",
    "get_default_loader",
    "prepare_model_input",
    "strip_html_tags",
]
