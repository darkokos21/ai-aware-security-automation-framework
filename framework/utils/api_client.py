from __future__ import annotations

from typing import Any

import requests

from framework.logging.logger import get_logger


class APIClient:
    """Simple HTTP client used by API security tests."""

    def __init__(
        self,
        base_url: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.logger = get_logger(
            self.__class__.__name__
        )
        self.session = requests.Session()

    def set_token(
        self,
        token: str,
    ) -> None:
        """Set a bearer token for subsequent requests."""

        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
            }
        )

    def clear_token(self) -> None:
        """Remove the configured bearer token."""

        self.session.headers.pop(
            "Authorization",
            None,
        )

    def get(
        self,
        endpoint: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a GET request."""

        url = f"{self.base_url}{endpoint}"

        self.logger.info(
            "GET %s",
            url,
        )

        return self.session.get(
            url,
            **kwargs,
        )

    def post(
        self,
        endpoint: str,
        json: Any = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a POST request."""

        url = f"{self.base_url}{endpoint}"

        self.logger.info(
            "POST %s",
            url,
        )

        return self.session.post(
            url,
            json=json,
            **kwargs,
        )

    def put(
        self,
        endpoint: str,
        json: Any = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a PUT request."""

        url = f"{self.base_url}{endpoint}"

        self.logger.info(
            "PUT %s",
            url,
        )

        return self.session.put(
            url,
            json=json,
            **kwargs,
        )

    def delete(
        self,
        endpoint: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a DELETE request."""

        url = f"{self.base_url}{endpoint}"

        self.logger.info(
            "DELETE %s",
            url,
        )

        return self.session.delete(
            url,
            **kwargs,
        )