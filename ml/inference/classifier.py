"""
MAILTRACE AI — DistilBERT email threat classifier.

Performs deterministic, in-memory inference on preprocessed 'Subject + Body' inputs.
Returns typed MlClassificationResult with 'BENIGN' or 'MALICIOUS' labels and confidence.
Operates under torch.no_grad() and model.eval().
"""

from __future__ import annotations

import time
from typing import Any

from forensics.email_parser.models import ParsedEmail
from ml.inference.loader import ModelLoader, get_default_loader
from ml.inference.models import (
    ClassificationLabel,
    MlClassificationResult,
    MlInferenceError,
    ModelInputError,
    ModelNotFoundError,
)
from ml.inference.preprocessing import DEFAULT_MAX_SEQUENCE_LENGTH, prepare_model_input

# Explicit mapping for dataset3_v1.0.0 classes
DEFAULT_LABEL_MAPPING: dict[int, ClassificationLabel] = {
    0: "BENIGN",
    1: "MALICIOUS",
}


def classify_email(
    email_input: ParsedEmail | str | dict[str, Any],
    loader: ModelLoader | None = None,
    max_length: int = DEFAULT_MAX_SEQUENCE_LENGTH,
) -> MlClassificationResult:
    """
    Classify an email as BENIGN or MALICIOUS using dataset3_v1.0.0 DistilBERT.

    Args:
        email_input: ParsedEmail, raw text, or dictionary containing subject and body.
        loader: Optional custom ModelLoader instance.
        max_length: Maximum sequence length for tokenizer truncation (default 512).

    Returns:
        Structured ``MlClassificationResult``.

    Raises:
        ModelNotFoundError: If model files are not found.
        ModelInputError: If input cannot be preprocessed.
        MlInferenceError: If inference fails during execution.
    """
    # 1. Preprocess input
    try:
        formatted_text = prepare_model_input(email_input)
    except Exception as exc:
        raise ModelInputError(f"Failed to preprocess email input: {exc}") from exc

    # 2. Obtain model and tokenizer
    active_loader = loader or get_default_loader()
    model, tokenizer = active_loader.load()

    # 3. Perform tokenization and inference under torch.no_grad()
    start_time = time.perf_counter()

    try:
        import torch

        device = active_loader.get_device()

        inputs = tokenizer(
            formatted_text,
            max_length=max_length,
            truncation=True,
            padding=True,
            return_tensors="pt",
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1).squeeze(0)

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        active_loader.record_inference_latency(latency_ms)

        # 4. Resolve label mapping
        id2label = getattr(model.config, "id2label", None)
        label_map = DEFAULT_LABEL_MAPPING
        if id2label and isinstance(id2label, dict):
            # Normalize config labels to uppercase BENIGN / MALICIOUS
            mapped: dict[int, ClassificationLabel] = {}
            for k, v in id2label.items():
                k_int = int(k)
                v_str = str(v).upper()
                if "MAL" in v_str or "PHISH" in v_str or "SPAM" in v_str or v_str == "1":
                    mapped[k_int] = "MALICIOUS"
                else:
                    mapped[k_int] = "BENIGN"
            if len(mapped) == 2:
                label_map = mapped

        # 5. Extract probabilities and predicted class
        probs_cpu = probs.cpu().tolist()
        if len(probs_cpu) == 1:
            # Single-logit binary output (sigmoid)
            p_malicious = float(probs_cpu[0])
            p_benign = 1.0 - p_malicious
            probabilities = {"BENIGN": round(p_benign, 4), "MALICIOUS": round(p_malicious, 4)}
            predicted_idx = 1 if p_malicious >= 0.5 else 0
        else:
            p_benign = float(probs_cpu[0])
            p_malicious = float(probs_cpu[1])
            probabilities = {"BENIGN": round(p_benign, 4), "MALICIOUS": round(p_malicious, 4)}
            predicted_idx = int(torch.argmax(probs).item())

        predicted_label: ClassificationLabel = label_map.get(predicted_idx, "BENIGN")
        confidence = probabilities[predicted_label]

        inference_metadata: dict[str, Any] = {
            "device": device,
            "latency_ms": latency_ms,
            "input_chars": len(formatted_text),
            "sequence_length": int(inputs["input_ids"].shape[-1]),
            "max_length": max_length,
        }

        return MlClassificationResult(
            label=predicted_label,
            confidence=confidence,
            probabilities=probabilities,
            model_version="dataset3_v1.0.0",
            inference_metadata=inference_metadata,
        )

    except (ModelNotFoundError, ModelInputError):
        raise
    except Exception as exc:
        raise MlInferenceError(f"Inference execution failed: {exc}") from exc
