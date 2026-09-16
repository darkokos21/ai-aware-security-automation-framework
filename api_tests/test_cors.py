from __future__ import annotations

import pytest


@pytest.mark.api
@pytest.mark.security
class TestCORS:

    def test_cors_does_not_allow_any_origin(
        self,
        api_client,
    ) -> None:
        response = api_client.get("/")

        allow_origin = response.headers.get(
            "Access-Control-Allow-Origin",
            "",
        )

        assert allow_origin != "*", (
            "The API allows requests from any origin "
            "using Access-Control-Allow-Origin: *."
        )