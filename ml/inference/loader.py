"""
MAILTRACE AI — Model loader for DistilBERT inference.

Provides lazy loading, caching, device management, and error handling for the
dataset3_v1.0.0 model. Ensures model weights are never loaded during package import.
Operates strictly in memory.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from backend.app.core.config import settings
except ImportError:
    settings = None
from ml.inference.models import ModelNotFoundError

DEFAULT_MODEL_DIR_NAME = "dataset3_v1.0.0"


class ModelLoader:
    """
    Lazy model loader for dataset3_v1.0.0 DistilBERT sequence classification.

    Attributes:
        model_path: Path to the local model directory.
        device: Target execution device ('cpu' or 'cuda').
    """

    def __init__(
        self,
        model_path: str | Path | None = None,
        device: str | None = None,
    ):
        self._configured_path = model_path
        self._configured_device = device
        self._model: Any = None
        self._tokenizer: Any = None

    def get_resolved_path(self) -> Path:
        """Resolve the model directory path from explicit param, settings, or env."""
        if self._configured_path:
            return Path(self._configured_path).resolve()

        env_path = os.getenv("ML_MODEL_PATH")
        if env_path:
            return Path(env_path).resolve()

        # Fall back to application settings
        try:
            if settings and hasattr(settings, "model_path"):
                return Path(settings.model_path).resolve()
        except Exception:  # noqa: BLE001
            pass

        # Fallback relative to repo root if settings cannot be loaded
        repo_root = Path(__file__).resolve().parents[2]
        return (repo_root / "ml" / "models" / DEFAULT_MODEL_DIR_NAME).resolve()

    def get_device(self) -> str:
        """Determine target execution device ('cuda' if available and requested, else 'cpu')."""
        if self._configured_device:
            return self._configured_device

        try:
            import torch
            return "cuda" if torch.cuda.is_available() else "cpu"
        except ImportError:
            return "cpu"

    def is_loaded(self) -> bool:
        """Return True if model and tokenizer are currently cached in memory."""
        return self._model is not None and self._tokenizer is not None

    def clear_cache(self) -> None:
        """Clear cached model and tokenizer from memory."""
        self._model = None
        self._tokenizer = None

    def load(self) -> tuple[Any, Any]:
        """
        Load tokenizer and model in evaluation mode with local files only.

        Returns:
            Tuple of ``(model, tokenizer)``.

        Raises:
            ModelNotFoundError: If the directory or weights do not exist.
        """
        if self.is_loaded():
            return self._model, self._tokenizer

        path = self.get_resolved_path()

        # Validate directory existence
        if not path.is_dir():
            raise ModelNotFoundError(
                f"Model directory not found: '{path}'. "
                "Ensure dataset3_v1.0.0 weights are placed in ml/models/dataset3_v1.0.0/ "
                "or configure ML_MODEL_PATH."
            )

        # Validate required model files
        config_file = path / "config.json"
        if not config_file.is_file():
            raise ModelNotFoundError(
                f"Model directory '{path}' is missing required 'config.json'."
            )

        has_weights = (
            (path / "model.safetensors").is_file()
            or (path / "pytorch_model.bin").is_file()
            or any(path.glob("*.safetensors"))
            or any(path.glob("*.bin"))
        )
        if not has_weights:
            raise ModelNotFoundError(
                f"Model directory '{path}' contains no weight files (model.safetensors or pytorch_model.bin)."
            )

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            device = self.get_device()

            # Load tokenizer with local_files_only to prevent automatic downloads
            tokenizer = AutoTokenizer.from_pretrained(
                str(path),
                local_files_only=True,
            )

            # Load model in eval mode
            model = AutoModelForSequenceClassification.from_pretrained(
                str(path),
                local_files_only=True,
            )
            model.to(device)
            model.eval()

            self._model = model
            self._tokenizer = tokenizer
            return self._model, self._tokenizer

        except ModelNotFoundError:
            raise
        except Exception as exc:
            raise ModelNotFoundError(
                f"Failed to load model from '{path}': {exc}"
            ) from exc


# Global singleton instance for convenient application-wide reuse
_global_loader: ModelLoader | None = None


def get_default_loader() -> ModelLoader:
    """Return the global singleton ``ModelLoader`` instance."""
    global _global_loader
    if _global_loader is None:
        _global_loader = ModelLoader()
    return _global_loader
