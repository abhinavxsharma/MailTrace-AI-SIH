"""Core application module containing configuration, logging, security, and middleware."""

from backend.app.core.config import get_settings, settings
from backend.app.core.exception_handlers import register_exception_handlers
from backend.app.core.exceptions import MailTraceException
from backend.app.core.logging import logger, request_id_ctx, setup_logging
from backend.app.core.middleware import RequestIDMiddleware

__all__ = [
    "settings",
    "get_settings",
    "logger",
    "setup_logging",
    "request_id_ctx",
    "RequestIDMiddleware",
    "register_exception_handlers",
    "MailTraceException",
]
