from __future__ import annotations

import time
from typing import Any

import requests

from framework.config.settings import settings
from framework.logging.logger import get_logger


class ZapClient:
    """Client for the OWASP ZAP HTTP API."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: int = 10,
    ) -> None:
        self.base_url = (base_url or settings.ZAP_URL).rstrip("/")
        self.api_key = api_key or settings.ZAP_API_KEY
        self.timeout = timeout
        self.logger = get_logger(self.__class__.__name__)

    def _request(
        self,
        component: str,
        operation: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """
        Send a request to the ZAP API.

        Each request has its own bounded network timeout so a stalled
        ZAP request cannot block the scanner indefinitely.
        """
        request_params = dict(params or {})

        if self.api_key:
            request_params["apikey"] = self.api_key

        url = f"{self.base_url}/JSON/{component}/{operation}/"

        request_timeout = (
            self.timeout
            if timeout is None
            else max(0.1, timeout)
        )

        self.logger.debug("ZAP API request: %s", url)

        response = requests.get(
            url,
            params=request_params,
            timeout=request_timeout,
        )

        response.raise_for_status()

        return response.json()

    def health_check(self) -> bool:
        """Return True when the ZAP API is reachable."""
        try:
            response = self._request(
                "core",
                "view/version",
            )
            return bool(response.get("version"))
        except requests.RequestException as exc:
            self.logger.warning(
                "ZAP health check failed: %s",
                exc,
            )
            return False

    def version(self) -> str:
        """Return the ZAP version."""
        response = self._request(
            "core",
            "view/version",
        )
        return str(response["version"])

    def new_session(
        self,
        name: str = "secure-test-ops",
    ) -> None:
        """Start a fresh ZAP session."""
        self.logger.info("Starting a fresh ZAP session.")

        self._request(
            "core",
            "action/newSession",
            {
                "name": name,
                "overwrite": "true",
            },
        )

    def access_url(self, url: str) -> dict[str, Any]:
        """Request that ZAP access the target URL."""
        return self._request(
            "core",
            "action/accessUrl",
            {
                "url": url,
            },
        )

    def spider(self, url: str) -> str:
        """Start a ZAP spider scan."""
        response = self._request(
            "spider",
            "action/scan",
            {
                "url": url,
                "recurse": "true",
            },
        )

        return str(response["scan"])

    def spider_status(self, scan_id: str) -> int:
        """Return spider progress percentage."""
        response = self._request(
            "spider",
            "view/status",
            {
                "scanId": scan_id,
            },
        )

        return int(response["status"])

    def wait_for_spider(
        self,
        scan_id: str,
        timeout: int = 120,
        poll_interval: int = 2,
    ) -> None:
        """Wait for the spider to complete within a hard deadline."""
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise TimeoutError(
                    "ZAP spider scan timed out."
                )

            request_timeout = min(
                float(self.timeout),
                max(0.1, remaining),
            )

            status = self._spider_status_with_timeout(
                scan_id,
                request_timeout,
            )

            if status >= 100:
                return

            sleep_time = min(
                float(poll_interval),
                max(
                    0.0,
                    deadline - time.monotonic(),
                ),
            )

            if sleep_time > 0:
                time.sleep(sleep_time)

    def _spider_status_with_timeout(
        self,
        scan_id: str,
        timeout: float,
    ) -> int:
        """Return spider status using a bounded API request."""
        response = self._request(
            "spider",
            "view/status",
            {
                "scanId": scan_id,
            },
            timeout=timeout,
        )

        return int(response["status"])

    def active_scan(self, url: str) -> str:
        """Start a ZAP active scan."""
        response = self._request(
            "ascan",
            "action/scan",
            {
                "url": url,
                "recurse": "true",
            },
        )

        return str(response["scan"])

    def active_scan_status(
        self,
        scan_id: str,
        timeout: float | None = None,
    ) -> int:
        """Return active-scan progress percentage."""
        response = self._request(
            "ascan",
            "view/status",
            {
                "scanId": scan_id,
            },
            timeout=timeout,
        )

        return int(response["status"])

    def stop_active_scan(
        self,
        scan_id: str,
        timeout: float | None = None,
    ) -> bool:
        """
        Request that ZAP stop an active scan.

        Returns True when ZAP accepts the stop request.
        """
        self.logger.warning(
            "Stopping ZAP active scan: %s",
            scan_id,
        )

        try:
            self._request(
                "ascan",
                "action/stop",
                {
                    "scanId": scan_id,
                },
                timeout=timeout,
            )

            return True

        except requests.RequestException as exc:
            self.logger.warning(
                "Unable to stop ZAP active scan %s: %s",
                scan_id,
                exc,
            )
            return False

    def wait_for_active_scan(
        self,
        scan_id: str,
        timeout: int = 600,
        poll_interval: int = 5,
    ) -> None:
        """
        Wait for an active scan using a hard overall deadline.

        The deadline includes both API requests and polling delays.
        If the deadline is reached, the running ZAP scan is stopped
        before TimeoutError is raised.
        """
        deadline = time.monotonic() + timeout

        self.logger.info(
            "Waiting for ZAP active scan %s with a %d-second timeout.",
            scan_id,
            timeout,
        )

        while True:
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                self.logger.warning(
                    "ZAP active scan timeout reached."
                )

                self._stop_active_scan_safely(
                    scan_id=scan_id,
                    deadline=deadline,
                )

                raise TimeoutError(
                    "ZAP active scan timed out and was stopped."
                )

            request_timeout = min(
                float(self.timeout),
                max(0.1, remaining),
            )

            try:
                status = self.active_scan_status(
                    scan_id,
                    timeout=request_timeout,
                )

            except requests.RequestException as exc:
                self.logger.warning(
                    "Unable to query ZAP active scan status: %s",
                    exc,
                )

                if time.monotonic() >= deadline:
                    self.logger.warning(
                        "ZAP active scan deadline reached after "
                        "a status-request failure."
                    )

                    self._stop_active_scan_safely(
                        scan_id=scan_id,
                        deadline=deadline,
                    )

                    raise TimeoutError(
                        "ZAP active scan timed out after "
                        "a status-request failure."
                    ) from exc

                retry_delay = min(
                    1.0,
                    max(
                        0.0,
                        deadline - time.monotonic(),
                    ),
                )

                if retry_delay > 0:
                    time.sleep(retry_delay)

                continue

            self.logger.info(
                "ZAP active scan progress: %d%%",
                status,
            )

            if status >= 100:
                return

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                self._stop_active_scan_safely(
                    scan_id=scan_id,
                    deadline=deadline,
                )

                raise TimeoutError(
                    "ZAP active scan timed out and was stopped."
                )

            time.sleep(
                min(
                    float(poll_interval),
                    remaining,
                )
            )

    def _stop_active_scan_safely(
        self,
        scan_id: str,
        deadline: float,
    ) -> None:
        """
        Attempt to stop an active scan without allowing cleanup
        to block indefinitely.

        Cleanup has its own short timeout so it can still be
        attempted after the main scan deadline has expired.
        """
        remaining = deadline - time.monotonic()

        cleanup_timeout = min(
            float(self.timeout),
            3.0,
        )

        if remaining > 0:
            cleanup_timeout = min(
                cleanup_timeout,
                remaining,
            )

        try:
            stopped = self.stop_active_scan(
                scan_id,
                timeout=max(0.1, cleanup_timeout),
            )

            if stopped:
                self.logger.info(
                    "ZAP active scan stop request completed: %s",
                    scan_id,
                )
            else:
                self.logger.warning(
                    "ZAP active scan stop request could not be "
                    "completed: %s",
                    scan_id,
                )

        except requests.RequestException as exc:
            self.logger.warning(
                "ZAP active-scan cleanup failed: %s",
                exc,
            )

    def alerts(
        self,
        base_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return ZAP alerts, optionally filtered by base URL."""
        params: dict[str, Any] = {}

        if base_url:
            params["baseurl"] = base_url

        response = self._request(
            "core",
            "view/alerts",
            params,
        )

        return list(response.get("alerts", []))