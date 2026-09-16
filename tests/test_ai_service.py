from framework.ai.models import (
    FindingSeverity,
    FindingSource,
    SecurityFinding,
    TriageResult,
)
from framework.ai.providers import SecurityTriageProvider
from framework.ai.service import SecurityTriageService


class FakeTriageProvider(SecurityTriageProvider):
    """
    Fake AI provider used for SecurityTriageService unit tests.
    """

    def triage(
        self,
        finding: SecurityFinding,
    ) -> TriageResult:
        return TriageResult(
            finding=finding,

            # Required fields in the current schema
            severity=FindingSeverity.HIGH,
            priority="high",
            confidence=0.95,
            explanation="Fake AI explanation of the vulnerability.",

            # Additional AI output fields
            impact="Fake impact.",
            remediation="Fake remediation.",
            rationale="Fake rationale.",
        )

    def generate_report(
        self,
        prompt: str,
    ) -> str:
        return (
            "# Executive Security Assessment\n\n"
            "Fake AI report."
        )

def _create_finding(
    title: str,
    severity: FindingSeverity,
) -> SecurityFinding:
    return SecurityFinding(
        title=title,
        description="Test finding description.",
        severity=severity,
        source=FindingSource.API,
    )


def test_service_triages_all_findings() -> None:
    findings = [
        _create_finding(
            "Finding one",
            FindingSeverity.HIGH,
        ),
        _create_finding(
            "Finding two",
            FindingSeverity.MEDIUM,
        ),
    ]

    service = SecurityTriageService(
        provider=FakeTriageProvider(),
    )

    results = service.triage_findings(findings)

    assert len(results) == 2

    assert results[0].finding.title == "Finding one"
    assert results[1].finding.title == "Finding two"

    assert results[0].priority == "high"
    assert results[1].priority == "high"


def test_service_returns_empty_list_for_no_findings() -> None:
    service = SecurityTriageService(
        provider=FakeTriageProvider(),
    )

    results = service.triage_findings([])

    assert results == []