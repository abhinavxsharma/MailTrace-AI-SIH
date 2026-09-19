"""
MAILTRACE AI — Structured logging configuration and factory.

Combines request-ID correlation tracing with structured JSON formatting
for all backend and intelligence modules.

Usage:
    from backend.app.core.logging import get_logger, logger, setup_logging
    # or
    from app.core.logging import get_logger

    log = get_logger(__name__)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextvars import ContextVar
from typing import Any

LOGGER_NAME = "mailtrace"
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | [%(request_id)s] %(name)s:%(lineno)d - %(message)s"

# Context variable tracking current HTTP request ID across async tasks
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


# --------------------------------------------------------------------------- #
# Request ID Filter                                                           #
# --------------------------------------------------------------------------- #

class RequestIDFilter(logging.Filter):
    """Logging filter that injects the active request ID into each log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get("-")
        return True


# --------------------------------------------------------------------------- #
# JSON Formatter                                                              #
# --------------------------------------------------------------------------- #

class _JsonFormatter(logging.Formatter):
    """
    Emit each log record as a single-line JSON object.

    Format:
        {"level": "INFO", "name": "app.services.mail.gmail_client",
         "message": "...", "request_id": "req_...", "exc_info": null}

    Using stdlib json only — no external dependencies.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        req_id = getattr(record, "request_id", None) or request_id_ctx.get("-")
        if req_id and req_id != "-":
            payload["request_id"] = req_id

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(payload, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Logger factory & setup                                                      #
# --------------------------------------------------------------------------- #

_LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO").upper()
_handler: logging.StreamHandler | None = None


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger configured with RequestIDFilter and JSON formatter.

    The logger hierarchy is respected — child loggers inherit the level from
    the root ``mailtrace`` logger, which is configured on first call.

    Args:
        name: Typically ``__name__`` of the calling module.

    Returns:
        A ``logging.Logger`` instance ready for use.
    """
    global _handler  # noqa: PLW0603

    if _handler is None:
        _handler = logging.StreamHandler(sys.stdout)
        _handler.addFilter(RequestIDFilter())
        _handler.setFormatter(_JsonFormatter())

    logger_inst = logging.getLogger(name)

    if not logger_inst.handlers:
        logger_inst.addHandler(_handler)
        logger_inst.propagate = False

    try:
        logger_inst.setLevel(getattr(logging, _LOG_LEVEL))
    except (AttributeError, TypeError):
        logger_inst.setLevel(logging.INFO)

    return logger_inst


def setup_logging() -> None:
    """Configure structured application logging with request ID correlation."""
    global _handler  # noqa: PLW0603

    try:
        from backend.app.core.config import settings
        log_level = logging.DEBUG if getattr(settings, "debug", False) else logging.INFO
    except Exception:
        log_level = logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RequestIDFilter())
    handler.setFormatter(_JsonFormatter())
    _handler = handler

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = [handler]

    # Suppress verbose third-party logging
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)


logger = get_logger(LOGGER_NAME)
