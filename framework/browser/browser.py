from __future__ import annotations

from typing import Any

from playwright.sync_api import Browser, BrowserContext, Page


class BrowserManager:
    """Playwright browser context manager."""

    def __init__(self, browser: Browser) -> None:
        self.browser = browser

    def create_context(self) -> BrowserContext:
        """Create a security-focused browser context."""

        return self.browser.new_context(
            ignore_https_errors=False,
            service_workers="block",
            viewport={
                "width": 1440,
                "height": 900,
            },
        )

    @staticmethod
    def headers(
        response: Any,
    ) -> dict[str, str]:
        """Normalize response headers to lowercase names."""

        if response is None:
            return {}

        return {
            key.lower(): value
            for key, value in response.headers.items()
        }

    @staticmethod
    def storage(
        page: Page,
    ) -> dict[str, list[str]]:
        """Return browser-storage key names without exposing values."""

        return page.evaluate(
            """
            () => ({
                localStorage: Object.keys(localStorage),
                sessionStorage: Object.keys(sessionStorage)
            })
            """
        )