from __future__ import annotations

from pathlib import Path

from framework.security_reporter import (
    API_FINDINGS,
    UI_FINDINGS,
    write_security_findings,
)


def _normalize_test_name(item) -> str:
    """
    Convert pytest parameterized names into stable lookup keys.

    Examples
    --------
    test_login_sql_injection_does_not_authenticate[' OR 1=1--]
        -> test_login_sql_injection_does_not_authenticate

    test_referrer_policy_is_configured[chromium]
        -> test_referrer_policy_is_configured

    test_security_headers_are_exposed[chromium]
        -> test_security_headers_are_exposed

    test_security_header_exists[Content-Security-Policy]
        -> test_security_header_exists[Content-Security-Policy]
        (keep parameter because each header is a different finding)
    """

    original = getattr(item, "originalname", None)

    # Keep the header parameterization intact.
    if original == "test_security_header_exists":
        return item.name

    # Use the original function name for every other parameterized test.
    return original or item.name.split("[")[0]


def pytest_configure(config) -> None:
    config._security_failed_tests = []


def pytest_runtest_makereport(item, call) -> None:
    if call.when != "call":
        return

    if call.excinfo is None:
        return

    if "security" not in item.keywords:
        return

    failed_tests = getattr(
        item.config,
        "_security_failed_tests",
        None,
    )

    if failed_tests is not None:
        failed_tests.append(_normalize_test_name(item))


def pytest_sessionfinish(session, exitstatus) -> None:
    failed_tests = getattr(
        session.config,
        "_security_failed_tests",
        [],
    )

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    if any(item.nodeid.startswith("api_tests/") for item in session.items):
        write_security_findings(
            failed_tests,
            reports_dir / "api-security-findings.json",
            API_FINDINGS,
        )

    if any(item.nodeid.startswith("ui_tests/") for item in session.items):
        write_security_findings(
            failed_tests,
            reports_dir / "ui-security-findings.json",
            UI_FINDINGS,
        )