"""
MAILTRACE AI — Structured logging factory.

Provides a consistent JSON-formatted logger for all backend modules.
All modules should obtain their logger via:

    from app.core.logging import get_logger
    logger = get_logger(__name__)

The log level defaults to INFO and can be overridden via the LOG_LEVEL
environment variable.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any


# --------------------------------------------------------------------------- #
# JSON formatter                                                               #
# --------------------------------------------------------------------------- #

class _JsonFormatter(logging.Formatter):
    """
    Emit each log record as a single-line JSON object.

    Format:
        {"level": "INFO", "name": "app.services.mail.gmail_client",
         "message": "...", "exc_info": null}

    Using stdlib json only — no external dependencies.
    """

    def format(self, record: logging.LogRecord) -> str:
        import json  # local import to keep module-level imports lean

        payload: dict[str, Any] = {
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(payload, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Logger factory                                                               #
# --------------------------------------------------------------------------- #

_LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO").upper()
_handler: logging.StreamHandler | None = None  # shared handler (lazy init)


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger configured with a JSON formatter.

    The logger hierarchy is respected — child loggers inherit the level from
    the root ``mailtrace`` logger, which is configured on first call.

    Args:
        name: Typically ``__name__`` of the calling module.

    Returns:
        A ``logging.Logger`` instance ready for use.
    """
    global _handler  # noqa: PLW0603

    # Configure the shared handler once.
    if _handler is None:
        _handler = logging.StreamHandler(sys.stdout)
        _handler.setFormatter(_JsonFormatter())

    logger = logging.getLogger(name)

    # Only configure if no handlers have been attached yet (avoids duplicate
    # output when the function is called multiple times for the same logger).
    if not logger.handlers:
        logger.addHandler(_handler)
        logger.propagate = False

    try:
        logger.setLevel(getattr(logging, _LOG_LEVEL))
    except AttributeError:
        logger.setLevel(logging.INFO)

    return logger
