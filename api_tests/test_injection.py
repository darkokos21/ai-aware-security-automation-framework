import pytest


SQLI_PAYLOADS = [
    "' OR 1=1--",
    '" OR "1"="1',
    "'; DROP TABLE Users; --",
]

XSS_PAYLOAD = "<script>alert('xss')</script>"


@pytest.mark.api
@pytest.mark.security
class TestInjection:

    @pytest.mark.parametrize(
        "payload",
        SQLI_PAYLOADS,
    )
    def test_login_sql_injection_does_not_authenticate(
        self,
        rest_client,
        payload,
    ):
        """
        Verify that SQL injection payloads cannot authenticate
        a user.

        Juice Shop exposes authentication through the /rest API.
        A successful authentication response contains an
        authentication token and authenticated user identity.

        Sensitive authentication tokens are deliberately never
        included in test failure messages or reports.
        """

        response = rest_client.post(
            "/user/login",
            json={
                "email": payload,
                "password": payload,
            },
        )

        if response.status_code == 200:
            data = response.json()

            authentication = data.get(
                "authentication",
                {},
            )

            token_present = bool(
                authentication.get("token")
            )

            authenticated_identity_present = bool(
                data.get("umail")
            )

            authentication_bypass_detected = (
                token_present
                or authenticated_identity_present
            )

            assert not authentication_bypass_detected, (
                "SQL injection payload successfully "
                "authenticated a user."
            )

            return

        assert response.status_code in (
            400,
            401,
            403,
        ), (
            "Unexpected response to SQL injection "
            f"payload: HTTP {response.status_code}."
        )

    def test_xss_payload_is_not_reflected(
        self,
        api_client,
    ):
        """
        Verify that an XSS payload is not reflected directly
        in the API response.
        """

        response = api_client.post(
            "/Feedbacks",
            json={
                "comment": XSS_PAYLOAD,
            },
        )

        assert XSS_PAYLOAD not in response.text, (
            "The submitted XSS payload was reflected "
            "directly in the API response."
        )