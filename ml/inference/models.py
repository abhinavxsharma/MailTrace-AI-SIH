"""
MAILTRACE AI — Domain models and exceptions for ML inference.

This module defines the typed output schema for DistilBERT classification
(dataset3_v1.0.0) and custom inference exception types.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

ClassificationLabel = Literal["BENIGN", "MALICIOUS"]


class MlClassificationResult(BaseModel):
    """
    Structured result of email threat classification via DistilBERT.

    Attributes:
        label: Predicted class label ('BENIGN' or 'MALICIOUS').
        confidence: Prediction confidence for the predicted label (0.0 to 1.0).
        probabilities: Full class probability distribution across all labels.
        model_version: Checkpoint identifier (always 'dataset3_v1.0.0').
        inference_metadata: Operational metadata (device, latency ms, input length).
    """

    model_config = {"frozen": True}

    label: Annotated[
        ClassificationLabel,
        Field(description="Classification verdict: 'BENIGN' or 'MALICIOUS'"),
    ]
    confidence: Annotated[
        float,
        Field(
            ge=0.0,
            le=1.0,
            description="Confidence score for predicted label (0.0 to 1.0)",
        ),
    ]
    probabilities: Annotated[
        dict[str, float],
        Field(
            default_factory=dict,
            description="Normalized class probabilities (e.g. {'BENIGN': 0.02, 'MALICIOUS': 0.98})",
        ),
    ]
    model_version: Annotated[
        str,
        Field(default="dataset3_v1.0.0", description="Model version tag"),
    ] = "dataset3_v1.0.0"
    inference_metadata: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Execution and hardware metadata"),
    ]


class MlInferenceError(Exception):
    """Base exception for all machine learning inference errors."""


class ModelNotFoundError(MlInferenceError):
    """Raised when the requested model checkpoint directory or weights cannot be found."""


class ModelInputError(MlInferenceError):
    """Raised when the input provided for inference cannot be parsed or preprocessed."""
