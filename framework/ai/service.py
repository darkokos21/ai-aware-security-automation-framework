from __future__ import annotations

from framework.ai.models import SecurityFinding, TriageResult
from framework.ai.providers import (
    DeterministicAIProvider,
    SecurityTriageProvider,
)


class SecurityTriageService:
    """
    High-level AI service responsible for triaging one or more
    normalized security findings.

    The service delegates the actual analysis to the configured
    provider (Deterministic or OpenAI).
    """

    def __init__(
        self,
        provider: SecurityTriageProvider | None = None,
    ) -> None:
        self.provider = provider or DeterministicAIProvider()

    def triage(
        self,
        finding: SecurityFinding,
    ) -> TriageResult:
        """
        Triage a single security finding.
        """
        return self.provider.triage(finding)

    def triage_findings(
        self,
        findings: list[SecurityFinding],
    ) -> list[TriageResult]:
        """
        Triage a collection of security findings.
        """

        return [
            self.provider.triage(finding)
            for finding in findings
        ]

    def generate_report(
        self,
        prompt: str,
    ) -> str:
        """
        Generate an executive AI security report using the
        configured provider.
        """

        return self.provider.generate_report(prompt)