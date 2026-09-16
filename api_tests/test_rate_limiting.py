import pytest


@pytest.mark.api
@pytest.mark.security
def test_login_rate_limiting_behavior(
    rest_client,
):
    """
    Evaluate HTTP-level rate limiting on the login endpoint.

    The intentionally vulnerable Juice Shop target does not
    currently return HTTP 429 responses for repeated invalid
    login attempts.

    This test records that behavior without treating the
    vulnerable target's lack of rate limiting as a test
    infrastructure failure.

    If HTTP rate limiting is introduced later, a 429 response
    will be detected and accepted as the expected security
    control.
    """

    responses = []

    for _ in range(15):
        responses.append(
            rest_client.post(
                "/user/login",
                json={
                    "email": "admin@juice-sh.op",
                    "password": "wrong_password",
                },
            )
        )

    status_codes = [
        response.status_code
        for response in responses
    ]

    if 429 in status_codes:
        return

    assert all(
        status_code == 401
        for status_code in status_codes
    ), (
        "Unexpected response pattern during repeated "
        f"login attempts: {status_codes}"
    )

    pytest.xfail(
        "Juice Shop does not currently demonstrate "
        "HTTP-level login rate limiting: no 429 response "
        "was observed after 15 repeated invalid attempts."
    )