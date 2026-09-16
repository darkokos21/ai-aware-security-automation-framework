from __future__ import annotations

import pytest


@pytest.mark.api
@pytest.mark.security
class TestInputValidation:

    def test_login_rejects_missing_email(
        self,
        rest_client,
    ) -> None:
        response = rest_client.post(
            "/user/login",
            json={
                "password": "invalid-password",
            },
        )

        assert response.status_code in {
            400,
            401,
            422,
        }, (
            "The login endpoint accepted a request "
            "without an email address. "
            f"Received status code: {response.status_code}"
        )

    def test_login_rejects_missing_password(
        self,
        rest_client,
    ) -> None:
        response = rest_client.post(
            "/user/login",
            json={
                "email": "invalid@example.com",
            },
        )

        assert response.status_code in {
            400,
            401,
            422,
        }, (
            "The login endpoint accepted a request "
            "without a password. "
            f"Received status code: {response.status_code}"
        )

    def test_login_rejects_invalid_field_types(
        self,
        rest_client,
    ) -> None:
        response = rest_client.post(
            "/user/login",
            json={
                "email": 12345,
                "password": True,
            },
        )

        assert response.status_code in {
            400,
            401,
            422,
        }, (
            "The login endpoint did not reject "
            "unexpected input types. "
            f"Received status code: {response.status_code}"
        )