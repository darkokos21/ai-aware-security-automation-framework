from __future__ import annotations

from zap.client import ZapClient
from zap.models import ZapAlert

from framework.config.settings import settings
from framework.logging.logger import get_logger


class ZapScanner:
    """Run an automated ZAP scan against the configured target."""

    def __init__(
        self,
        client: ZapClient | None = None,
    ) -> None:
        self.client = client or ZapClient()
        self.logger = get_logger(
            self.__class__.__name__
        )

    def run(
        self,
        target_url: str | None = None,
        active: bool = False,
        active_timeout: int = 600,
    ) -> list[ZapAlert]:
        """
        Run a ZAP spider scan and optionally an active scan.

        A fresh ZAP session is created for every scan so that
        findings from previous scans are not accumulated.

        Active scanning is disabled by default because it can
        perform intrusive security testing against the target.
        """

        target = (
            target_url or settings.ZAP_TARGET_URL
        ).rstrip("/")

        self.logger.info(
            "Starting ZAP scan against %s",
            target,
        )

        self.client.new_session()
        self.client.access_url(target)

        spider_id = self.client.spider(target)

        self.logger.info(
            "Started ZAP spider: %s",
            spider_id,
        )

        self.client.wait_for_spider(
            spider_id
        )

        if active:
            self.logger.info(
                "Starting ZAP active scan against %s",
                target,
            )

            scan_id = self.client.active_scan(
                target
            )

            self.logger.info(
                "Started ZAP active scan: %s",
                scan_id,
            )

            self.client.wait_for_active_scan(
                scan_id,
                timeout=active_timeout,
            )

        raw_alerts = self.client.alerts(
            target
        )

        alerts = [
            self._normalize_alert(alert)
            for alert in raw_alerts
        ]

        self.logger.info(
            "ZAP scan completed. Raw findings: %d",
            len(alerts),
        )

        return alerts

    @staticmethod
    def _normalize_alert(
        alert: dict,
    ) -> ZapAlert:
        """Convert a raw ZAP alert into a normalized model."""

        return ZapAlert(
            name=str(
                alert.get("alert")
                or alert.get("name")
                or "Unknown finding"
            ),
            risk=str(
                alert.get("risk")
                or "Informational"
            ),
            confidence=str(
                alert.get("confidence")
                or "Unknown"
            ),
            url=str(
                alert.get("url")
                or ""
            ),
            description=str(
                alert.get("description")
                or ""
            ),
            solution=str(
                alert.get("solution")
                or ""
            ),
            reference=str(
                alert.get("reference")
                or ""
            ),
            cwe_id=str(
                alert.get("cweid")
                or ""
            ),
            wasc_id=str(
                alert.get("wascid")
                or ""
            ),
        )