"""
MAILTRACE AI — Model loader for DistilBERT inference.

Provides lazy loading, caching, device management, and error handling for the
dataset3_v1.0.0 model. Ensures model weights are never loaded during package import.
Operates strictly in memory.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

try:
    from backend.app.core.config import settings
except ImportError:
    settings = None
from ml.inference.models import ModelNotFoundError

DEFAULT_MODEL_DIR_NAME = "dataset3_v1.0.0"


def find_repo_root() -> Path:
    """Locate repository root portably by searching parents for known markers."""
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / "ml" / "models").is_dir() or (parent / "backend").is_dir():
            return parent
    return Path(__file__).resolve().parents[2]


class ModelLoader:
    """
    Thread-safe lazy model loader for dataset3_v1.0.0 DistilBERT sequence classification.

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
        self._lock = threading.Lock()
        self._load_time_ms: float | None = None
        self._warmup_time_ms: float | None = None
        self._last_inference_latency_ms: float | None = None
        self._warm: bool = False
        self._load_error: str | None = None

    def get_resolved_path(self) -> Path:
        """Resolve the model directory path from explicit param, env, settings, or repo root."""
        repo_root = find_repo_root()

        raw_target: str | Path | None = None
        if self._configured_path is not None:
            raw_target = self._configured_path
        elif os.getenv("ML_MODEL_PATH"):
            raw_target = os.getenv("ML_MODEL_PATH")
        elif settings and hasattr(settings, "ML_MODEL_PATH") and settings.ML_MODEL_PATH:
            raw_target = settings.ML_MODEL_PATH
        elif settings and hasattr(settings, "model_path") and settings.model_path:
            raw_target = settings.model_path

        if raw_target is None:
            raw_target = repo_root / "ml" / "models" / DEFAULT_MODEL_DIR_NAME

        candidate = Path(raw_target)

        # 1. Absolute path
        if candidate.is_absolute():
            target = candidate.resolve()
        else:
            # 2. Relative path: check repo root first, then CWD
            if (repo_root / candidate).exists():
                target = (repo_root / candidate).resolve()
            elif (Path.cwd() / candidate).exists():
                target = (Path.cwd() / candidate).resolve()
            else:
                target = (repo_root / candidate).resolve()

        # 3. If target points to a parent directory containing DEFAULT_MODEL_DIR_NAME
        if target.is_dir() and not (target / "config.json").is_file():
            sub = target / DEFAULT_MODEL_DIR_NAME
            if (sub / "config.json").is_file():
                return sub.resolve()

        return target

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
        with self._lock:
            self._model = None
            self._tokenizer = None
            self._warm = False
            self._load_time_ms = None
            self._warmup_time_ms = None
            self._last_inference_latency_ms = None
            self._load_error = None

    def record_inference_latency(self, latency_ms: float) -> None:
        """Record the execution latency of the most recent classification inference."""
        self._last_inference_latency_ms = round(latency_ms, 2)

    def warm_up(self) -> bool:
        """
        Execute a lightweight dry-run inference to warm up model weights and runtime caches.

        Returns:
            True if warm-up succeeded, False if model unavailable or failed.
        """
        if self._warm and self.is_loaded():
            return True

        with self._lock:
            if self._warm and self.is_loaded():
                return True

            try:
                # 1. Load model and tokenizer
                model, tokenizer = self._load_internal()
                import torch

                device = self.get_device()
                t0 = time.perf_counter()

                # 2. Minimal realistic dummy input
                sample_text = "Subject: Service Security Notification\n\nBody: Routine system verification notice."
                inputs = tokenizer(
                    sample_text,
                    max_length=128,
                    truncation=True,
                    padding=True,
                    return_tensors="pt",
                )
                inputs = {k: v.to(device) for k, v in inputs.items()}

                with torch.no_grad():
                    _ = model(**inputs)

                self._warmup_time_ms = round((time.perf_counter() - t0) * 1000, 2)
                self._warm = True
                self._load_error = None
                return True

            except Exception as exc:
                self._load_error = str(exc)
                self._warm = False
                return False

    def get_health(self) -> dict[str, Any]:
        """
        Return safe, production-grade ML health and readiness diagnostics.

        Does not leak local paths, user names, or security secrets.
        """
        loaded = self.is_loaded()
        device = self.get_device()
        status = "ready" if (loaded and self._warm) else ("loaded" if loaded else "unavailable")

        metrics: dict[str, Any] = {
            "load_time_ms": self._load_time_ms,
            "warmup_time_ms": self._warmup_time_ms,
            "last_inference_latency_ms": self._last_inference_latency_ms,
        }

        response: dict[str, Any] = {
            "status": status,
            "model": DEFAULT_MODEL_DIR_NAME,
            "loaded": loaded,
            "device": device,
            "warm": self._warm and loaded,
            "metrics": metrics,
        }
        if not loaded and self._load_error:
            # Report high-level error without disclosing private local filesystem paths
            response["details"] = "Model weights not found or failed to load. Operating in heuristic fallback mode."
        return response

    def _load_internal(self) -> tuple[Any, Any]:
        """Internal uncached loader logic executed under self._lock."""
        if self.is_loaded():
            return self._model, self._tokenizer

        path = self.get_resolved_path()

        # Validate directory existence
        if not path.is_dir():
            raise ModelNotFoundError(
                f"Model directory not found: '{path.name}'. "
                "Ensure dataset3_v1.0.0 weights are placed in ml/models/dataset3_v1.0.0/ "
                "or configure ML_MODEL_PATH."
            )

        # Validate required model files
        config_file = path / "config.json"
        if not config_file.is_file():
            raise ModelNotFoundError(
                f"Model directory '{path.name}' is missing required 'config.json'."
            )

        has_weights = (
            (path / "model.safetensors").is_file()
            or (path / "pytorch_model.bin").is_file()
            or any(path.glob("*.safetensors"))
            or any(path.glob("*.bin"))
        )
        if not has_weights:
            raise ModelNotFoundError(
                f"Model directory '{path.name}' contains no weight files (model.safetensors or pytorch_model.bin)."
            )

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            device = self.get_device()
            t0 = time.perf_counter()

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

            self._load_time_ms = round((time.perf_counter() - t0) * 1000, 2)
            self._model = model
            self._tokenizer = tokenizer
            self._load_error = None
            return self._model, self._tokenizer

        except ModelNotFoundError:
            raise
        except Exception as exc:
            self._load_error = str(exc)
            raise ModelNotFoundError(
                f"Failed to load model '{path.name}': {exc}"
            ) from exc

    def load(self) -> tuple[Any, Any]:
        """
        Thread-safe singleton load for tokenizer and model in evaluation mode.

        Returns:
            Tuple of ``(model, tokenizer)``.

        Raises:
            ModelNotFoundError: If the directory or weights do not exist.
        """
        if self.is_loaded():
            return self._model, self._tokenizer

        with self._lock:
            if self.is_loaded():
                return self._model, self._tokenizer
            model, tokenizer = self._load_internal()
            self._model = model
            self._tokenizer = tokenizer
            return self._model, self._tokenizer


# Global singleton instance for convenient application-wide reuse
_global_loader: ModelLoader | None = None
_global_lock = threading.Lock()


def get_default_loader() -> ModelLoader:
    """Return the global singleton ``ModelLoader`` instance."""
    global _global_loader
    if _global_loader is None:
        with _global_lock:
            if _global_loader is None:
                _global_loader = ModelLoader()
    return _global_loader


def get_ml_health() -> dict[str, Any]:
    """Convenience helper returning the ML health state of the global loader."""
    return get_default_loader().get_health()


def warm_up_default_loader() -> bool:
    """Convenience helper warming up the default global loader."""
    return get_default_loader().warm_up()
