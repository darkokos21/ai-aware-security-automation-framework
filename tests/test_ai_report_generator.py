from __future__ import annotations

from framework.ai.models import (
    FindingSeverity,
    FindingSource,
    SecurityFinding,
    TriagePriority,
    TriageResult,
)
from framework.ai.providers import DeterministicTriageProvider
from framework.ai.report_generator import SecurityReportGenerator


def make_finding(
    title: str,
    source: FindingSource,
    severity: FindingSeverity,
    sources: list[FindingSource] | None = None,
) -> SecurityFinding:
    """Create a minimal SecurityFinding for report-generator tests."""

    finding_sources = sources or [source]

    return SecurityFinding(
        title=title,
        description=f"Description for {title}",
        severity=severity,
        source=source,
        confidence=1.0,
        endpoint="/",
        evidence="Test evidence",
        remediation="Test remediation",
        cwe_id="693",
        sources=finding_sources,
        source_count=len(finding_sources),
    )


def make_result(
    title: str,
    source: FindingSource,
    severity: FindingSeverity,
    priority: TriagePriority,
    sources: list[FindingSource] | None = None,
) -> TriageResult:
    """Create a TriageResult for report-generator tests."""

    finding = make_finding(
        title=title,
        source=source,
        severity=severity,
        sources=sources,
    )

    return TriageResult(
        finding=finding,
        priority=priority,
        severity=severity,
        confidence=1.0,
        explanation="Test explanation",
        impact="Test impact",
        remediation="Test remediation",
        rationale="Test rationale",
    )


def test_report_generator_returns_markdown() -> None:
    """
    Verify that the detailed report generator produces Markdown
    containing the expected finding information.
    """

    result = make_result(
        title="SQL injection authentication bypass",
        source=FindingSource.API,
        severity=FindingSeverity.CRITICAL,
        priority=TriagePriority.CRITICAL,
    )

    generator = SecurityReportGenerator()

    report = generator.generate([result])

    assert "# Security Triage Report" in report
    assert "Total findings: 1" in report
    assert "SQL injection authentication bypass" in report
    assert "**Priority:** critical" in report
    assert "**Severity:** critical" in report
    assert "**Confidence:** 1.00" in report
    assert "**Source:** api" in report
    assert "### Explanation" in report
    assert "### Impact" in report
    assert "### Remediation" in report
    assert "### Rationale" in report


def test_empty_report() -> None:
    """
    Verify that an empty result collection produces a useful
    Markdown message instead of an invalid report.
    """

    generator = SecurityReportGenerator()

    report = generator.generate([])

    assert report == (
        "# Security Triage Report\n\n"
        "No security findings were identified."
    )


def test_executive_summary_contains_dynamic_priority_counts() -> None:
    """
    Verify that the executive summary calculates priority counts
    dynamically from the supplied triage results.
    """

    results = [
        make_result(
            title="Critical finding",
            source=FindingSource.API,
            severity=FindingSeverity.CRITICAL,
            priority=TriagePriority.CRITICAL,
        ),
        make_result(
            title="High finding",
            source=FindingSource.UI,
            severity=FindingSeverity.MEDIUM,
            priority=TriagePriority.HIGH,
        ),
        make_result(
            title="Medium finding",
            source=FindingSource.API,
            severity=FindingSeverity.MEDIUM,
            priority=TriagePriority.MEDIUM,
        ),
        make_result(
            title="Second medium finding",
            source=FindingSource.ZAP,
            severity=FindingSeverity.MEDIUM,
            priority=TriagePriority.MEDIUM,
        ),
        make_result(
            title="Low finding",
            source=FindingSource.UI,
            severity=FindingSeverity.LOW,
            priority=TriagePriority.LOW,
        ),
        make_result(
            title="Informational finding",
            source=FindingSource.ZAP,
            severity=FindingSeverity.INFORMATIONAL,
            priority=TriagePriority.INFORMATIONAL,
        ),
    ]

    generator = SecurityReportGenerator()

    report = generator._generate_executive_report(results)

    assert "## Executive Summary" in report
    assert "### Findings by Priority" in report

    assert "- **Critical:** 1" in report
    assert "- **High:** 1" in report
    assert "- **Medium:** 2" in report
    assert "- **Low:** 1" in report
    assert "- **Informational:** 1" in report

    assert "**Total findings:** 6" in report


def test_executive_summary_lists_security_sources() -> None:
    """
    Verify that the executive summary identifies the security
    testing sources represented in the assessment.
    """

    results = [
        make_result(
            title="ZAP finding",
            source=FindingSource.ZAP,
            severity=FindingSeverity.MEDIUM,
            priority=TriagePriority.MEDIUM,
        ),
        make_result(
            title="API finding",
            source=FindingSource.API,
            severity=FindingSeverity.MEDIUM,
            priority=TriagePriority.MEDIUM,
        ),
        make_result(
            title="UI finding",
            source=FindingSource.UI,
            severity=FindingSeverity.LOW,
            priority=TriagePriority.LOW,
        ),
    ]

    generator = SecurityReportGenerator()

    report = generator._generate_executive_report(results)

    assert "### Sources" in report
    assert "- ZAP" in report
    assert "- API security tests" in report
    assert "- UI security tests" in report


def test_executive_summary_reports_cross_source_correlations() -> None:
    """
    Verify that findings detected by multiple independent sources
    are represented in the executive summary.
    """

    correlated_sources = [
        FindingSource.ZAP,
        FindingSource.API,
        FindingSource.UI,
    ]

    results = [
        make_result(
            title="Cross-source CSP finding",
            source=FindingSource.ZAP,
            severity=FindingSeverity.MEDIUM,
            priority=TriagePriority.HIGH,
            sources=correlated_sources,
        ),
        make_result(
            title="API-only finding",
            source=FindingSource.API,
            severity=FindingSeverity.MEDIUM,
            priority=TriagePriority.MEDIUM,
        ),
    ]

    generator = SecurityReportGenerator()

    report = generator._generate_executive_report(results)

    assert "### Cross-Source Correlations" in report
    assert (
        "- 1 finding detected across multiple independent "
        "security sources"
    ) in report


def test_executive_report_uses_provider_name() -> None:
    """
    Verify that the executive report identifies the configured
    triage provider.
    """

    provider = DeterministicTriageProvider()
    generator = SecurityReportGenerator(provider)

    result = make_result(
        title="Test finding",
        source=FindingSource.API,
        severity=FindingSeverity.MEDIUM,
        priority=TriagePriority.MEDIUM,
    )

    report = generator._generate_executive_report([result])

    assert "**Provider:** Deterministic provider" in report


def test_generate_markdown_report_triages_findings() -> None:
    """
    Verify the public generate_markdown_report workflow:

    raw findings
        -> provider triage
        -> executive report
    """

    provider = DeterministicTriageProvider()
    generator = SecurityReportGenerator(provider)

    finding = make_finding(
        title="Content Security Policy header is missing",
        source=FindingSource.API,
        severity=FindingSeverity.MEDIUM,
    )

    report = generator.generate_markdown_report([finding])

    assert "# Executive Security Assessment" in report
    assert "**Provider:** Deterministic provider" in report
    assert "Content Security Policy header is missing" in report
    assert "## Executive Summary" in report
    assert "**Total findings:** 1" in report