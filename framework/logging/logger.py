from __future__ import annotations

import logging
import sys

from framework.config.settings import settings


def get_logger(name: str) -> logging.Logger:
    """Create and configure a project logger."""

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(
        getattr(
            logging,
            settings.LOG_LEVEL.upper(),
            logging.INFO,
        )
    )

    handler = logging.StreamHandler(sys.stdout)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

    return logger