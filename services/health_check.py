from __future__ import annotations

import requests

from framework.config.settings import settings
from framework.logging.logger import get_logger
from zap.client import ZapClient


logger = get_logger(__name__)


def check_application() -> bool:
    """Check whether the configured application is reachable."""

    try:
        response = requests.get(
            settings.BASE_URL,
            timeout=10,
        )

        response.raise_for_status()

        return True

    except requests.RequestException as exc:
        logger.warning(
            "Application health check failed: %s",
            exc,
        )

        return False


def check_zap() -> bool:
    """Check whether the ZAP API is reachable."""

    return ZapClient().health_check()


def check_all() -> bool:
    """Return True when both application and ZAP are reachable."""

    application_ok = check_application()
    zap_ok = check_zap()

    return application_ok and zap_ok