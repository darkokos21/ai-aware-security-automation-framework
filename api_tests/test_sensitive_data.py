from __future__ import annotations

import pytest


SENSITIVE_RESPONSE_KEYS = {
    "password",
    "passwordhash",
    "password_hash",
    "privatekey",
    "private_key",
    "secretkey",
    "secret_key",
    "refreshtoken",
    "refresh_token",
}


def _find_sensitive_keys(
    payload: object,
) -> list[str]:
    """Recursively find suspicious keys in a JSON response."""

    findings: list[str] = []

    if isinstance(payload, dict):
        for key, value in payload.items():
            normalized_key = str(key).replace("-", "").lower()

            if normalized_key in SENSITIVE_RESPONSE_KEYS:
                findings.append(str(key))

            findings.extend(
                _find_sensitive_keys(value)
            )

    elif isinstance(payload, list):
        for item in payload:
            findings.extend(
                _find_sensitive_keys(item)
            )

    return findings


@pytest.mark.api
@pytest.mark.security
class TestSensitiveDataExposure:

    def test_public_api_does_not_expose_sensitive_fields(
        self,
        api_client,
    ) -> None:
        response = api_client.get("/")

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if "application/json" not in content_type:
            pytest.skip(
                "The endpoint does not return JSON."
            )

        payload = response.json()
        sensitive_keys = _find_sensitive_keys(payload)

        assert not sensitive_keys, (
            "Potentially sensitive fields were exposed "
            "in the API response: "
            + ", ".join(sorted(set(sensitive_keys)))
        )