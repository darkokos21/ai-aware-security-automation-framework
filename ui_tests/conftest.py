from collections.abc import Generator

import pytest
from playwright.sync_api import Browser, BrowserContext, Page

from framework.browser.browser import BrowserManager
from framework.config.settings import settings


@pytest.fixture
def browser_context(
    browser: Browser,
) -> Generator[BrowserContext, None, None]:
    """
    Create an isolated browser context for each test.
    """

    manager = BrowserManager(
        browser=browser,
    )

    context = manager.create_context()

    yield context

    context.close()


@pytest.fixture
def page(
    browser_context: BrowserContext,
) -> Generator[Page, None, None]:
    """
    Create an isolated browser page for each test.
    """

    page = browser_context.new_page()

    yield page

    page.close()


@pytest.fixture(scope="session")
def base_url() -> str:
    """Return the configured application URL."""

    return settings.BASE_URL.rstrip("/")