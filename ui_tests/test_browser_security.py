from __future__ import annotations

from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page

from framework.browser.browser import BrowserManager


SENSITIVE_TERMS = {
    "private_key",
    "privatekey",
    "secret_key",
    "secretkey",
    "password=",
    "aws_access_key",
}


@pytest.mark.ui
@pytest.mark.security
class TestBrowserSecurity:

    def test_security_headers_are_exposed(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        response = page.goto(base_url)

        assert response is not None

        headers = BrowserManager.headers(response)

        security_headers = {
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        }

        missing_headers = [
            header
            for header in security_headers
            if header not in headers
        ]

        assert not missing_headers, (
            "Missing security headers: "
            + ", ".join(sorted(missing_headers))
        )

    def test_content_type_options_prevents_mime_sniffing(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        response = page.goto(base_url)

        assert response is not None

        headers = BrowserManager.headers(response)

        assert headers.get(
            "x-content-type-options",
            "",
        ).lower() == "nosniff", (
            "X-Content-Type-Options should be set to 'nosniff'."
        )

    def test_clickjacking_protection_is_configured(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        response = page.goto(base_url)

        assert response is not None

        headers = BrowserManager.headers(response)

        x_frame_options = headers.get(
            "x-frame-options",
            "",
        ).lower()

        csp = headers.get(
            "content-security-policy",
            "",
        ).lower()

        x_frame_protected = x_frame_options in {
            "deny",
            "sameorigin",
        }

        csp_protected = (
            "frame-ancestors" in csp
            and (
                "'none'" in csp
                or "'self'" in csp
            )
        )

        assert x_frame_protected or csp_protected, (
            "No effective clickjacking protection "
            "was detected."
        )

    def test_referrer_policy_is_configured(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        response = page.goto(base_url)

        assert response is not None

        headers = BrowserManager.headers(response)

        assert headers.get("referrer-policy"), (
            "Referrer-Policy header is missing."
        )

    def test_sensitive_storage_keys_are_not_present_after_initial_load(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        page.goto(base_url)

        storage = BrowserManager.storage(page)

        sensitive_terms = {
            "password",
            "passwd",
            "secret",
            "authorization",
            "access_token",
            "refresh_token",
        }

        storage_keys = (
            storage["localStorage"]
            + storage["sessionStorage"]
        )

        suspicious_keys = [
            key
            for key in storage_keys
            if any(
                term in key.lower()
                for term in sensitive_terms
            )
        ]

        assert not suspicious_keys, (
            "Potentially sensitive data found in "
            "browser storage keys: "
            + ", ".join(suspicious_keys)
        )

    def test_cookies_have_security_attributes(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        page.goto(base_url)

        cookies = page.context.cookies()

        sensitive_cookie_terms = {
            "session",
            "auth",
            "token",
            "jwt",
        }

        sensitive_cookies = [
            cookie
            for cookie in cookies
            if any(
                term in cookie["name"].lower()
                for term in sensitive_cookie_terms
            )
        ]

        if not sensitive_cookies:
            pytest.skip(
                "No authentication/session-related "
                "cookies were detected."
            )

        insecure_cookies: list[str] = []

        for cookie in sensitive_cookies:
            problems: list[str] = []

            if not cookie.get("httpOnly", False):
                problems.append("HttpOnly")

            if not cookie.get("sameSite"):
                problems.append("SameSite")

            if problems:
                insecure_cookies.append(
                    f"{cookie['name']}: "
                    + ", ".join(problems)
                )

        assert not insecure_cookies, (
            "Sensitive cookies are missing recommended "
            "security attributes: "
            + "; ".join(insecure_cookies)
        )

    def test_page_source_does_not_contain_obvious_secrets(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        page.goto(base_url)

        content = page.content().lower()

        exposed_terms = [
            term
            for term in SENSITIVE_TERMS
            if term in content
        ]

        assert not exposed_terms, (
            "Potentially sensitive information was found "
            "in the loaded page source: "
            + ", ".join(sorted(exposed_terms))
        )

    def test_external_resources_are_identifiable(
        self,
        page: Page,
        base_url: str,
    ) -> None:
        page.goto(base_url)

        base_origin = urlparse(base_url).netloc

        resources = page.evaluate(
            """
            () => Array.from(
                document.querySelectorAll(
                    'script[src], link[href], img[src]'
                )
            ).map(element => ({
                tag: element.tagName.toLowerCase(),
                url: element.src || element.href
            }))
            """
        )

        external_resources = [
            resource
            for resource in resources
            if urlparse(resource["url"]).netloc
            and urlparse(resource["url"]).netloc != base_origin
        ]

        if external_resources:
            page.evaluate(
                """
                resources => {
                    console.info(
                        "External resources detected:",
                        resources
                    );
                }
                """,
                external_resources,
            )

        assert isinstance(
            external_resources,
            list,
        )