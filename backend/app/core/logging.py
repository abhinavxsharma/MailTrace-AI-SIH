"""Application logging configuration with request correlation tracing."""

import logging
import sys
from contextvars import ContextVar

from backend.app.core.config import settings

LOGGER_NAME = "mailtrace"
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | [%(request_id)s] %(name)s:%(lineno)d - %(message)s"

# Context variable tracking current HTTP request ID across async tasks
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIDFilter(logging.Filter):
    """Logging filter that injects the active request ID into each log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get("-")
        return True


def setup_logging() -> None:
    """Configure structured application logging with request ID correlation."""
    log_level = logging.DEBUG if settings.debug else logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RequestIDFilter())
    handler.setFormatter(logging.Formatter(LOG_FORMAT))

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = [handler]

    # Suppress verbose third-party logging
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)


logger = logging.getLogger(LOGGER_NAME)
