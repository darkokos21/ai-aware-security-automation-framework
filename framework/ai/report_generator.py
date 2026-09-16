from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from framework.ai.models import SecurityFinding, TriageResult


class SecurityReportGenerator:
    """
    Generate human-readable security reports.

    The generator supports two workflows:

    1. Generate a report from already-created TriageResult objects.
    2. Accept a triage provider and raw SecurityFinding objects,
       triage them, and generate an executive Markdown report.

    The executive report includes:
    - dynamic priority counts
    - security sources represented in the assessment
    - cross-source correlation count
    - total finding count
    - detailed finding-level analysis
    """

    def __init__(
        self,
        provider: object | None = None,
    ) -> None:
        self.provider = provider

    def generate(
        self,
        results: Iterable[TriageResult],
    ) -> str:
        """
        Generate a detailed Markdown security triage report from
        already-created TriageResult objects.
        """

        result_list = list(results)

        if not result_list:
            return (
                "# Security Triage Report\n\n"
                "No security findings were identified."
            )

        lines: list[str] = [
            "# Security Triage Report",
            "",
            f"Total findings: {len(result_list)}",
            "",
        ]

        for index, result in enumerate(result_list, start=1):
            finding = result.finding

            lines.extend(
                [
                    f"## {index}. {finding.title}",
                    "",
                    f"- **Priority:** {result.priority}",
                    f"- **Severity:** {result.severity.value}",
                    f"- **Confidence:** {result.confidence:.2f}",
                    f"- **Source:** {finding.source.value}",
                    f"- **Endpoint:** {finding.endpoint or 'N/A'}",
                    "",
                    "### Explanation",
                    "",
                    result.explanation,
                    "",
                    "### Impact",
                    "",
                    result.impact,
                    "",
                    "### Remediation",
                    "",
                    result.remediation,
                    "",
                    "### Rationale",
                    "",
                    result.rationale,
                    "",
                ]
            )

        return "\n".join(lines)

    def generate_from_findings(
        self,
        findings: Iterable[SecurityFinding],
    ) -> str:
        """
        Triage raw security findings using the configured provider
        and generate the executive Markdown security assessment.
        """

        if self.provider is None:
            raise ValueError(
                "A triage provider is required when generating "
                "a report directly from security findings."
            )

        finding_list = list(findings)

        if not finding_list:
            return (
                "# Executive Security Assessment\n\n"
                "No findings were detected."
            )

        triage_results = [
            self.provider.triage(finding)
            for finding in finding_list
        ]

        return self._generate_executive_report(triage_results)

    def generate_markdown_report(
        self,
        findings: Iterable[SecurityFinding],
    ) -> str:
        """
        Generate the executive Markdown security assessment from
        raw security findings.
        """

        return self.generate_from_findings(findings)

    def _get_provider_name(self) -> str:
        """
        Return a human-readable provider name for the report.
        """

        if self.provider is None:
            return "Unknown provider"

        provider_name = self.provider.__class__.__name__

        provider_names = {
            "DeterministicAIProvider": "Deterministic provider",
            "DeterministicTriageProvider": "Deterministic provider",
            "OpenAITriageProvider": "OpenAI provider",
        }

        return provider_names.get(
            provider_name,
            provider_name,
        )

    def _build_executive_summary(
        self,
        results: list[TriageResult],
    ) -> list[str]:
        """
        Build a dynamic executive summary from triage results.

        The summary includes:
        - findings grouped by remediation priority
        - security sources represented in the assessment
        - cross-source correlation count
        - total findings
        """

        priority_counts = Counter(
            result.priority.value
            for result in results
        )

        source_labels = {
            "zap": "ZAP",
            "api": "API security tests",
            "ui": "UI security tests",
        }

        sources = sorted(
            {
                source_labels.get(
                    result.finding.source.value,
                    result.finding.source.value,
                )
                for result in results
            }
        )

        cross_source_count = sum(
            1
            for result in results
            if len(result.finding.sources) > 1
        )

        lines: list[str] = [
            "## Executive Summary",
            "",
            "### Findings by Priority",
            "",
            f"- **Critical:** "
            f"{priority_counts.get('critical', 0)}",
            f"- **High:** "
            f"{priority_counts.get('high', 0)}",
            f"- **Medium:** "
            f"{priority_counts.get('medium', 0)}",
            f"- **Low:** "
            f"{priority_counts.get('low', 0)}",
            f"- **Informational:** "
            f"{priority_counts.get('informational', 0)}",
            "",
            "### Sources",
            "",
        ]

        for source in sources:
            lines.append(f"- {source}")

        lines.extend(
            [
                "",
                "### Cross-Source Correlations",
                "",
                (
                    f"- {cross_source_count} finding"
                    f"{'' if cross_source_count == 1 else 's'} "
                    "detected across multiple independent "
                    "security sources"
                ),
                "",
                f"**Total findings:** {len(results)}",
                "",
                "---",
                "",
            ]
        )

        return lines

    def _generate_executive_report(
        self,
        results: Iterable[TriageResult],
    ) -> str:
        """
        Generate an executive-oriented Markdown security assessment.
        """

        result_list = list(results)

        if not result_list:
            return (
                "# Executive Security Assessment\n\n"
                "No findings were detected."
            )

        lines: list[str] = [
            "# Executive Security Assessment",
            "",
            f"**Provider:** {self._get_provider_name()}",
            "",
        ]

        lines.extend(
            self._build_executive_summary(result_list)
        )

        for index, result in enumerate(result_list, start=1):
            finding = result.finding

            lines.extend(
                [
                    f"## {index}. {finding.title}",
                    "",
                    f"- **Priority:** {result.priority.value}",
                    f"- **Severity:** {result.severity.value}",
                    f"- **Confidence:** {result.confidence:.2f}",
                    f"- **Source:** {finding.source.value}",
                    f"- **Endpoint:** {finding.endpoint or 'N/A'}",
                    "",
                    "### Explanation",
                    "",
                    result.explanation,
                    "",
                    "### Impact",
                    "",
                    result.impact,
                    "",
                    "### Remediation",
                    "",
                    result.remediation,
                    "",
                    "### Rationale",
                    "",
                    result.rationale,
                    "",
                ]
            )

        return "\n".join(lines)

    def generate_markdown(
        self,
        results: Iterable[TriageResult],
    ) -> str:
        """Backward-compatible alias for generate()."""

        return self.generate(results)

    def build_report(
        self,
        results: Iterable[TriageResult],
    ) -> str:
        """Backward-compatible alias for generate()."""

        return self.generate(results)

    def create_report(
        self,
        findings: Iterable[SecurityFinding],
    ) -> str:
        """
        Backward-compatible convenience method.

        Accepts raw security findings, triages them using the configured
        provider, and returns the executive Markdown assessment.
        """

        return self.generate_from_findings(findings)


# Backward-compatible aliases used by existing tests and callers.
ReportGenerator = SecurityReportGenerator
AISecurityReportGenerator = SecurityReportGenerator