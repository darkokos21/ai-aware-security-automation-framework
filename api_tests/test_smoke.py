import pytest


@pytest.mark.api
@pytest.mark.smoke
def test_api_configuration_loaded(api_client):
    """
    Verify that the API client has a valid HTTP base URL.
    """

    assert api_client.base_url.startswith(
        ("http://", "https://")
    ), (
        "API client base URL is not configured with "
        "a valid HTTP or HTTPS scheme."
    )