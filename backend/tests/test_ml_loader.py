"""
Tests for ML model loader (ml.inference.loader).

Covers:
- Lazy loading (no model loaded on module/package import)
- Missing model directory raises ModelNotFoundError
- Missing config.json raises ModelNotFoundError
- Missing weight files raises ModelNotFoundError
- Model caching and clear_cache()
- Device resolution (CPU / CUDA)
- Model evaluation mode (model.eval())
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ml.inference.loader import ModelLoader
from ml.inference.models import ModelNotFoundError


class TestModelLoader:

    def test_no_model_loaded_on_init(self):
        loader = ModelLoader(model_path="some/fake/path")
        assert loader.is_loaded() is False

    def test_missing_directory_raises_model_not_found_error(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist"
        loader = ModelLoader(model_path=str(nonexistent))

        with pytest.raises(ModelNotFoundError) as exc_info:
            loader.load()
        assert "not found" in str(exc_info.value).lower()

    def test_missing_config_json_raises_model_not_found_error(self, tmp_path):
        model_dir = tmp_path / "bad_model"
        model_dir.mkdir()
        # Create weight file but no config.json
        (model_dir / "model.safetensors").write_bytes(b"dummy weights")

        loader = ModelLoader(model_path=str(model_dir))
        with pytest.raises(ModelNotFoundError) as exc_info:
            loader.load()
        assert "config.json" in str(exc_info.value)

    def test_missing_weights_raises_model_not_found_error(self, tmp_path):
        model_dir = tmp_path / "no_weights_model"
        model_dir.mkdir()
        # Create config.json but no weight files
        (model_dir / "config.json").write_text("{}", encoding="utf-8")

        loader = ModelLoader(model_path=str(model_dir))
        with pytest.raises(ModelNotFoundError) as exc_info:
            loader.load()
        assert "weight files" in str(exc_info.value).lower()

    def test_lazy_loading_and_caching(self, tmp_path):
        model_dir = tmp_path / "valid_model"
        model_dir.mkdir()
        (model_dir / "config.json").write_text("{}", encoding="utf-8")
        (model_dir / "model.safetensors").write_bytes(b"dummy")

        mock_model = MagicMock()
        mock_tokenizer = MagicMock()

        loader = ModelLoader(model_path=str(model_dir))
        assert loader.is_loaded() is False

        with patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer) as mock_tok_load, \
             patch("transformers.AutoModelForSequenceClassification.from_pretrained", return_value=mock_model) as mock_model_load:

            m1, t1 = loader.load()
            assert loader.is_loaded() is True
            assert m1 == mock_model
            assert t1 == mock_tokenizer
            mock_tok_load.assert_called_once()
            mock_model_load.assert_called_once()
            mock_model.eval.assert_called_once()

            # Second call should use cached instances without re-loading
            m2, t2 = loader.load()
            assert m2 == m1
            assert t2 == t1
            assert mock_tok_load.call_count == 1
            assert mock_model_load.call_count == 1

            # Test clear_cache()
            loader.clear_cache()
            assert loader.is_loaded() is False

    def test_device_selection(self):
        loader_cpu = ModelLoader(device="cpu")
        assert loader_cpu.get_device() == "cpu"

        loader_cuda = ModelLoader(device="cuda")
        assert loader_cuda.get_device() == "cuda"
