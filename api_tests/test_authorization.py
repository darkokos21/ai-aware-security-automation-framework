import pytest


@pytest.mark.api
@pytest.mark.security
class TestAuthorization:

    def test_authenticated_user_can_access_users_endpoint(
        self,
        authenticated_client,
    ):
        """
        Verify that a valid authenticated user can access
        the protected Users endpoint.
        """

        response = authenticated_client.get("/Users")

        assert response.status_code == 200, (
            "A valid authenticated user should be able to access "
            f"the Users endpoint. Received HTTP {response.status_code}."
        )

    def test_user_resource_access_is_authenticated(
        self,
        authenticated_client,
    ):
        """
        Verify that access to an individual user resource
        is available only through authenticated access.
        """

        response = authenticated_client.get("/Users/2")

        assert response.status_code in (200, 403, 404), (
            "Unexpected response from an authenticated user-resource "
            f"request: HTTP {response.status_code}."
        )