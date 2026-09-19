"""Core application module containing configuration, logging, and security."""

from backend.app.core.config import get_settings, settings
from backend.app.core.logging import logger, setup_logging

__all__ = ["settings", "get_settings", "logger", "setup_logging"]
