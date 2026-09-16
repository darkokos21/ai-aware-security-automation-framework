from framework.ai.models import (
    FindingSeverity,
    FindingSource,
    SecurityFinding,
    TriagePriority,
)
from framework.ai.triage import SecurityTriageEngine


def test_critical_sql_injection_receives_critical_priority() -> None:
    finding = SecurityFinding(
        title="SQL injection authentication bypass",
        description=(
            "A SQL injection payload successfully "
            "authenticated against the login endpoint."
        ),
        severity=FindingSeverity.CRITICAL,
        source=FindingSource.API,
        confidence=1.0,
        endpoint="/rest/user/login",
        evidence="' OR 1=1--",
        cwe_id="89",
        test_name="test_login_sql_injection_does_not_authenticate",
        sources=[FindingSource.API],
        source_count=1,
    )

    result = SecurityTriageEngine().triage(
        finding
    )

    assert result.severity == FindingSeverity.CRITICAL
    assert result.priority == TriagePriority.CRITICAL
    assert result.confidence == 1.0
    assert "SQL injection" in result.explanation
    assert "database" in result.impact
    assert "parameterized" in result.remediation


def test_multi_source_medium_finding_receives_high_priority() -> None:
    finding = SecurityFinding(
        title="Content Security Policy header is missing",
        severity=FindingSeverity.MEDIUM,
        source=FindingSource.API,
        confidence=1.0,
        cwe_id="693",
        sources=[
            FindingSource.API,
            FindingSource.UI,
            FindingSource.ZAP,
        ],
        source_count=3,
    )

    result = SecurityTriageEngine().triage(
        finding
    )

    assert result.severity == FindingSeverity.MEDIUM
    assert result.priority == TriagePriority.HIGH
    assert result.confidence == 1.0
    assert "3 independent" in result.rationale


def test_low_finding_receives_low_priority() -> None:
    finding = SecurityFinding(
        title="Timestamp Disclosure - Unix",
        severity=FindingSeverity.LOW,
        source=FindingSource.ZAP,
        confidence=0.95,
        sources=[FindingSource.ZAP],
        source_count=1,
    )

    result = SecurityTriageEngine().triage(
        finding
    )

    assert result.priority == TriagePriority.LOW
    assert result.severity == FindingSeverity.LOW
    assert result.confidence == 0.95