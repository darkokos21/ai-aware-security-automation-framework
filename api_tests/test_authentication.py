import pytest


@pytest.mark.api
@pytest.mark.security
class TestAuthentication:

    def test_users_endpoint_requires_authentication(
        self,
        api_client,
    ):
        """
        Access the protected Users API without authentication.
        """

        response = api_client.get("/Users")

        assert response.status_code in (401, 403), (
            "The Users endpoint should reject unauthenticated access. "
            f"Received HTTP {response.status_code}."
        )

    def test_invalid_jwt_token_is_rejected(
        self,
        api_client,
    ):
        """
        Send an invalid bearer token to a protected endpoint.
        """

        api_client.set_token(
            "this.is.not.a.valid.jwt"
        )

        response = api_client.get("/Users")

        assert response.status_code in (401, 403), (
            "An invalid JWT should not grant access. "
            f"Received HTTP {response.status_code}."
        )

    def test_empty_bearer_token_is_rejected(
        self,
        api_client,
    ):
        """
        Send an empty bearer token to a protected endpoint.
        """

        api_client.session.headers.update(
            {
                "Authorization": "Bearer ",
            }
        )

        response = api_client.get("/Users")

        assert response.status_code in (401, 403), (
            "An empty bearer token should not grant access. "
            f"Received HTTP {response.status_code}."
        )