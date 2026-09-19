"""Application logging configuration."""

import logging
import sys

from backend.app.core.config import settings

LOGGER_NAME = "mailtrace"
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s"


def setup_logging() -> None:
    """Configure standard application logging."""
    log_level = logging.DEBUG if settings.debug else logging.INFO

    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
        force=True,
    )

    # Set logger levels for third-party libraries if needed
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)


logger = logging.getLogger(LOGGER_NAME)
