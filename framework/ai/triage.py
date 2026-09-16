from __future__ import annotations

from framework.ai.models import (
    FindingSeverity,
    SecurityFinding,
    TriagePriority,
    TriageResult,
)


class SecurityTriageEngine:
    """
    Analyze security findings and produce triage results.

    This first implementation is deterministic. It provides
    a reliable fallback when no external LLM provider is
    configured.
    """

    def triage(
        self,
        finding: SecurityFinding,
    ) -> TriageResult:
        """Generate a triage result for one finding."""

        severity = finding.severity

        priority = self._determine_priority(
            finding
        )

        confidence = self._determine_confidence(
            finding
        )

        explanation = self._build_explanation(
            finding
        )

        impact = self._build_impact(
            finding
        )

        remediation = self._build_remediation(
            finding
        )

        rationale = self._build_rationale(
            finding,
            priority,
        )

        return TriageResult(
            finding=finding,
            priority=priority,
            severity=severity,
            confidence=confidence,
            explanation=explanation,
            impact=impact,
            remediation=remediation,
            rationale=rationale,
        )

    @staticmethod
    def _determine_priority(
        finding: SecurityFinding,
    ) -> TriagePriority:
        """Determine remediation priority."""

        if finding.severity == FindingSeverity.CRITICAL:
            return TriagePriority.CRITICAL

        if finding.severity == FindingSeverity.HIGH:
            return TriagePriority.HIGH

        if (
            finding.severity == FindingSeverity.MEDIUM
            and finding.source_count >= 2
        ):
            return TriagePriority.HIGH

        if finding.severity == FindingSeverity.MEDIUM:
            return TriagePriority.MEDIUM

        if finding.severity == FindingSeverity.LOW:
            return TriagePriority.LOW

        return TriagePriority.INFORMATIONAL

    @staticmethod
    def _determine_confidence(
        finding: SecurityFinding,
    ) -> float:
        """Determine triage confidence."""

        confidence = finding.confidence

        if finding.source_count >= 3:
            confidence += 0.10
        elif finding.source_count >= 2:
            confidence += 0.05

        return min(
            1.0,
            confidence,
        )

    @staticmethod
    def _build_explanation(
        finding: SecurityFinding,
    ) -> str:
        """Build a human-readable security explanation."""

        if finding.description:
            return finding.description

        return (
            f"The security check identified "
            f"{finding.title.lower()}."
        )

    @staticmethod
    def _build_impact(
        finding: SecurityFinding,
    ) -> str:
        """Build an impact statement."""

        title = finding.title.lower()

        if "sql injection" in title:
            return (
                "An attacker may manipulate database queries "
                "through untrusted input, potentially bypassing "
                "authentication or accessing unauthorized data."
            )

        if "cors" in title or "cross-domain" in title:
            return (
                "An overly permissive cross-origin policy may "
                "allow untrusted websites to interact with the "
                "application in unintended ways."
            )

        if "content security policy" in title:
            return (
                "Without an effective Content Security Policy, "
                "the application has reduced protection against "
                "certain client-side injection and script "
                "execution attacks."
            )

        if "referrer" in title:
            return (
                "Sensitive URL information may be exposed to "
                "external destinations through the HTTP Referer "
                "header."
            )

        if "trace" in title:
            return (
                "An improperly handled TRACE method can expose "
                "unnecessary HTTP functionality and may increase "
                "the application's attack surface."
            )

        if "invalid input" in title:
            return (
                "Unexpected input can trigger server errors, "
                "which may expose implementation details and "
                "indicate insufficient input validation."
            )

        return (
            "The identified security weakness may increase "
            "the application's attack surface or reduce its "
            "defensive controls."
        )

    @staticmethod
    def _build_remediation(
        finding: SecurityFinding,
    ) -> str:
        """Build a remediation recommendation."""

        if finding.remediation:
            return finding.remediation

        title = finding.title.lower()

        if "sql injection" in title:
            return (
                "Use parameterized queries or prepared statements "
                "and validate authentication input server-side."
            )

        if "cors" in title or "cross-domain" in title:
            return (
                "Restrict allowed origins to trusted application "
                "origins and avoid wildcard cross-origin access "
                "where credentials or sensitive data are involved."
            )

        if "content security policy" in title:
            return (
                "Define and return an appropriate "
                "Content-Security-Policy header."
            )

        if "referrer" in title:
            return (
                "Configure an appropriate Referrer-Policy response "
                "header."
            )

        if "trace" in title:
            return (
                "Disable TRACE or reject it with a controlled "
                "HTTP response."
            )

        if "invalid input" in title:
            return (
                "Validate request schemas and reject invalid "
                "input types with controlled 4xx responses."
            )

        return (
            "Review the affected component and apply the "
            "security control recommended by the finding."
        )

    @staticmethod
    def _build_rationale(
        finding: SecurityFinding,
        priority: TriagePriority,
    ) -> str:
        """Explain why the finding received its priority."""

        source_text = ", ".join(
            source.value.upper()
            for source in (
                finding.sources
                or [finding.source]
            )
        )

        if finding.source_count > 1:
            return (
                f"The finding was detected by {finding.source_count} "
                f"independent security sources ({source_text}), "
                f"which increases confidence that the issue is "
                f"real and raises its remediation priority to "
                f"{priority.value.upper()}."
            )

        return (
            f"The finding was detected by {source_text}. "
            f"Its current severity and available evidence "
            f"support a {priority.value.upper()} remediation priority."
        )