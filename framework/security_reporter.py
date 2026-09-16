from __future__ import annotations

import json
from pathlib import Path
from typing import Any


API_FINDINGS: dict[str, dict[str, Any]] = {
    "test_cors_does_not_allow_any_origin": {
        "title": "CORS allows any origin",
        "description": "The API responds with Access-Control-Allow-Origin: *.",
        "severity": "medium",
        "endpoint": "/api",
        "remediation": "Restrict allowed origins to trusted application origins.",
        "cwe_id": "942",
    },
    "test_security_header_exists[Content-Security-Policy]": {
        "title": "Content Security Policy header is missing",
        "description": (
            "The application does not return a "
            "Content-Security-Policy header."
        ),
        "severity": "medium",
        "endpoint": "/",
        "remediation": "Define and return an appropriate Content-Security-Policy.",
        "cwe_id": "693",
    },
    "test_trace_method_is_not_enabled": {
        "title": "TRACE HTTP method is not safely rejected",
        "description": (
            "The server returns HTTP 500 when receiving a TRACE request."
        ),
        "severity": "medium",
        "endpoint": "/",
        "remediation": (
            "Disable TRACE or reject it with an appropriate "
            "4xx/5xx response without generating a server error."
        ),
        "cwe_id": "749",
    },
    "test_login_sql_injection_does_not_authenticate": {
        "title": "SQL injection authentication bypass",
        "description": (
            "A SQL injection payload successfully authenticated "
            "against the login endpoint."
        ),
        "severity": "critical",
        "endpoint": "/rest/user/login",
        "remediation": (
            "Use parameterized queries or prepared statements "
            "and validate authentication input server-side."
        ),
        "cwe_id": "89",
    },
    "test_login_rejects_invalid_field_types": {
        "title": "Invalid input types cause HTTP 500",
        "description": (
            "Unexpected JSON field types cause an internal server "
            "error instead of controlled validation failure."
        ),
        "severity": "medium",
        "endpoint": "/rest/user/login",
        "remediation": (
            "Validate request schema and reject invalid types "
            "with a controlled 4xx response."
        ),
        "cwe_id": "20",
    },
}


UI_FINDINGS: dict[str, dict[str, Any]] = {
    "test_security_headers_are_exposed": {
        "title": "Content Security Policy header is missing",
        "description": (
            "The application does not return a "
            "Content-Security-Policy header."
        ),
        "severity": "medium",
        "endpoint": "/",
        "remediation": "Define and return an appropriate Content-Security-Policy.",
        "cwe_id": "693",
    },
    "test_referrer_policy_is_configured": {
        "title": "Referrer-Policy header is missing",
        "description": (
            "The application does not return a Referrer-Policy header."
        ),
        "severity": "low",
        "endpoint": "/",
        "remediation": (
            "Configure an appropriate Referrer-Policy response header."
        ),
        "cwe_id": "693",
    },
}


def write_security_findings(
    failed_tests: list[str],
    output_path: str | Path,
    finding_definitions: dict[str, dict[str, Any]],
) -> Path:
    """Write normalized findings for failed security tests."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    findings: list[dict[str, Any]] = []

    for test_name in failed_tests:
        definition = finding_definitions.get(test_name)

        if definition is None:
            continue

        finding = {
            **definition,
            "confidence": 1.0,
            "evidence": f"Security test failed: {test_name}",
            "test_name": test_name,
        }

        findings.append(finding)

    output.write_text(
        json.dumps(
            findings,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return output