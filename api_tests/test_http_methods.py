from __future__ import annotations

import pytest


@pytest.mark.api
@pytest.mark.security
class TestHTTPMethods:

    def test_trace_method_is_not_enabled(
        self,
        api_client,
    ) -> None:
        response = api_client.session.request(
            "TRACE",
            f"{api_client.base_url}/",
            timeout=10,
        )

        assert response.status_code in {
            400,
            404,
            405,
            501,
        }, (
            "TRACE HTTP method appears to be enabled. "
            f"Received status code: {response.status_code}"
        )