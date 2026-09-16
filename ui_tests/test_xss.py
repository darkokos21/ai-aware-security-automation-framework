import pytest
from playwright.sync_api import Page, expect


@pytest.mark.ui
@pytest.mark.security
class TestXSSProtection:

    XSS_PAYLOAD = "<img src=x onerror=alert('xss')>"

    def test_xss_payload_is_not_executed(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        """
        Verify that an XSS payload does not execute as JavaScript.

        The test uses a harmless browser-side marker rather than
        interacting with the operating system or external resources.
        """
        page.goto(f"{base_url}/#/search")

        page.wait_for_load_state("domcontentloaded")

        search_input = page.locator(
            "input[placeholder*='search' i]"
        ).first

        if not search_input.is_visible():
            pytest.skip("Search input is not available on this version of Juice Shop.")

        dialog_triggered = False

        def handle_dialog(dialog) -> None:
            nonlocal dialog_triggered
            dialog_triggered = True
            dialog.dismiss()

        page.on("dialog", handle_dialog)

        search_input.fill(self.XSS_PAYLOAD)
        search_input.press("Enter")

        page.wait_for_timeout(1000)

        assert not dialog_triggered, (
            "Potential XSS detected: injected JavaScript triggered a dialog."
        )

    def test_xss_payload_is_not_rendered_as_html(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        """
        Verify that an injected HTML payload is not interpreted as an
        executable DOM element where the application reflects it.
        """
        page.goto(f"{base_url}/#/search")

        page.wait_for_load_state("domcontentloaded")

        search_input = page.locator(
            "input[placeholder*='search' i]"
        ).first

        if not search_input.is_visible():
            pytest.skip("Search input is not available on this version of Juice Shop.")

        search_input.fill(self.XSS_PAYLOAD)
        search_input.press("Enter")

        page.wait_for_timeout(1000)

        injected_images = page.locator(
            "img[src='x']"
        )

        expect(injected_images).to_have_count(0)