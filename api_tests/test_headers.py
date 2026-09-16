import pytest


EXPECTED_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
]


@pytest.mark.api
@pytest.mark.security
class TestSecurityHeaders:

    @pytest.mark.parametrize(
        "header",
        EXPECTED_HEADERS,
    )
    def test_security_header_exists(
        self,
        api_client,
        header,
    ):
        """
        Verify that required security headers are present
        in the application response.

        Missing security headers are treated as security
        findings rather than infrastructure failures.
        """

        response = api_client.get("/")

        response_headers = {
            name.lower()
            for name in response.headers
        }

        assert header.lower() in response_headers, (
            f"Required security header '{header}' "
            "is missing from the application response."
        )