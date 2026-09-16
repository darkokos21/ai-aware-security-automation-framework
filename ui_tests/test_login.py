import pytest
from playwright.sync_api import Page


@pytest.mark.ui
@pytest.mark.smoke
class TestLogin:

    def test_application_is_reachable(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        """Verify that the configured application is reachable."""
        response = page.goto(base_url)

        assert response is not None
        assert response.ok, (
            f"Application returned HTTP {response.status}: {base_url}"
        )

    def test_login_page_is_available(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        """
        Verify that the login page can be reached.

        Juice Shop uses /#/login for its client-side login route.
        """
        response = page.goto(f"{base_url}/#/login")

        assert response is not None
        assert response.ok

        page.wait_for_load_state("domcontentloaded")

        assert page.url.startswith(f"{base_url}/#/login")