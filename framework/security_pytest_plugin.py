from __future__ import annotations

from pathlib import Path

from framework.security_reporter import (
    API_FINDINGS,
    UI_FINDINGS,
    write_security_findings,
)


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
        failed_tests.append(item.name)


def pytest_sessionfinish(session, exitstatus) -> None:
    failed_tests = getattr(
        session.config,
        "_security_failed_tests",
        [],
    )

    root = Path("reports")

    if any(
        item.nodeid.startswith("api_tests/")
        for item in session.items
    ):
        write_security_findings(
            failed_tests,
            root / "api-security-findings.json",
            API_FINDINGS,
        )

    if any(
        item.nodeid.startswith("ui_tests/")
        for item in session.items
    ):
        write_security_findings(
            failed_tests,
            root / "ui-security-findings.json",
            UI_FINDINGS,
        )