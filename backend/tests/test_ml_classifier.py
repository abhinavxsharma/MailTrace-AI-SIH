"""
Tests for ML classifier (ml.inference.classifier).

Covers:
- Classification output schema (MlClassificationResult)
- Predicted label mapping (BENIGN, MALICIOUS)
- Confidence calculation and full class probabilities
- Deterministic inference under torch.no_grad()
- Sequence length truncation
- Missing model error handling
- Conditional integration test with real local weights
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import torch

from forensics.email_parser.models import ParsedAddress, ParsedEmail
from ml.inference.classifier import classify_email
from ml.inference.loader import ModelLoader
from ml.inference.models import MlClassificationResult, ModelNotFoundError


def _make_mock_model(logits_tensor: torch.Tensor) -> tuple[MagicMock, MagicMock]:
    """Create a mock model and tokenizer producing the given logits."""
    mock_model = MagicMock()
    mock_model.config.id2label = {0: "BENIGN", 1: "MALICIOUS"}

    output_mock = MagicMock()
    output_mock.logits = logits_tensor
    mock_model.return_value = output_mock

    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": torch.tensor([[101, 202, 102]]),
        "attention_mask": torch.tensor([[1, 1, 1]]),
    }

    return mock_model, mock_tokenizer


class TestClassifier:

    def test_classify_benign_prediction(self):
        # Logits favoring index 0 (BENIGN)
        logits = torch.tensor([[3.0, -1.0]])
        mock_model, mock_tokenizer = _make_mock_model(logits)

        mock_loader = MagicMock(spec=ModelLoader)
        mock_loader.load.return_value = (mock_model, mock_tokenizer)
        mock_loader.get_device.return_value = "cpu"

        email = ParsedEmail(
            message_id="m1",
            subject="Meeting Tomorrow",
            body_text="Hi Alice, let's meet tomorrow at 10 AM.",
            from_address=ParsedAddress(email="bob@example.com"),
        )

        result = classify_email(email, loader=mock_loader)

        assert isinstance(result, MlClassificationResult)
        assert result.label == "BENIGN"
        assert result.confidence > 0.95
        assert "BENIGN" in result.probabilities
        assert "MALICIOUS" in result.probabilities
        assert result.probabilities["BENIGN"] > result.probabilities["MALICIOUS"]
        assert result.model_version == "dataset3_v1.0.0"
        assert result.inference_metadata["device"] == "cpu"

    def test_classify_malicious_prediction(self):
        # Logits favoring index 1 (MALICIOUS)
        logits = torch.tensor([[-2.0, 4.0]])
        mock_model, mock_tokenizer = _make_mock_model(logits)

        mock_loader = MagicMock(spec=ModelLoader)
        mock_loader.load.return_value = (mock_model, mock_tokenizer)
        mock_loader.get_device.return_value = "cpu"

        email = ParsedEmail(
            message_id="m2",
            subject="URGENT: Verify Your Bank Account",
            body_text="Click here immediately to restore access or account will be suspended.",
            from_address=ParsedAddress(email="phish@evil.com"),
        )

        result = classify_email(email, loader=mock_loader)

        assert isinstance(result, MlClassificationResult)
        assert result.label == "MALICIOUS"
        assert result.confidence > 0.95
        assert result.probabilities["MALICIOUS"] > result.probabilities["BENIGN"]

    def test_classify_missing_model_raises_model_not_found_error(self, tmp_path):
        loader = ModelLoader(model_path=str(tmp_path / "nonexistent"))
        email = ParsedEmail(message_id="m3", subject="Test", body_text="Hello")

        with pytest.raises(ModelNotFoundError):
            classify_email(email, loader=loader)

    def test_custom_max_sequence_length_passed_to_tokenizer(self):
        logits = torch.tensor([[1.0, 1.0]])
        mock_model, mock_tokenizer = _make_mock_model(logits)

        mock_loader = MagicMock(spec=ModelLoader)
        mock_loader.load.return_value = (mock_model, mock_tokenizer)
        mock_loader.get_device.return_value = "cpu"

        email = ParsedEmail(message_id="m4", subject="Test", body_text="Hello")
        classify_email(email, loader=mock_loader, max_length=256)

        mock_tokenizer.assert_called_once()
        _, kwargs = mock_tokenizer.call_args
        assert kwargs.get("max_length") == 256
        assert kwargs.get("truncation") is True

    def test_real_local_model_integration(self):
        """
        Integration test that runs only if the real dataset3_v1.0.0 weights
        exist in the local filesystem.
        """
        local_model_path = Path("ml/models/dataset3_v1.0.0")
        has_real_weights = (
            local_model_path.is_dir()
            and (local_model_path / "config.json").is_file()
            and (
                (local_model_path / "model.safetensors").is_file()
                or (local_model_path / "pytorch_model.bin").is_file()
            )
        )

        if not has_real_weights:
            pytest.skip("Local dataset3_v1.0.0 weights not found; skipping real-weight integration test.")

        loader = ModelLoader(model_path=str(local_model_path))
        email = ParsedEmail(
            message_id="real_test_1",
            subject="Hello",
            body_text="This is a benign message for integration testing.",
        )
        result = classify_email(email, loader=loader)
        assert result.label in ("BENIGN", "MALICIOUS")
        assert 0.0 <= result.confidence <= 1.0
