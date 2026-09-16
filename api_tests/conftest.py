import pytest

from framework.config.settings import settings
from framework.utils.api_client import APIClient


@pytest.fixture
def api_client() -> APIClient:
    """
    Create a fresh unauthenticated client for the /api endpoints.
    """

    return APIClient(settings.API_URL)


@pytest.fixture
def rest_client() -> APIClient:
    """
    Create a fresh unauthenticated client for the /rest endpoints.

    Juice Shop uses the /rest API for authentication-related
    operations such as POST /rest/user/login.
    """

    return APIClient(settings.REST_API_URL)


@pytest.fixture
def authenticated_client(api_client: APIClient) -> APIClient:
    """
    Create an authenticated API client for tests that require JWT access.

    The JWT must be supplied through the local .env file.
    """

    if not settings.JWT_TOKEN:
        pytest.skip(
            "JWT_TOKEN is not configured; "
            "authenticated API test skipped."
        )

    api_client.set_token(settings.JWT_TOKEN)

    return api_client