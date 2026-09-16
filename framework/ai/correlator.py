from __future__ import annotations

from collections.abc import Iterable

from framework.ai.models import SecurityFinding


class SecurityFindingCorrelator:
    """
    Correlate security findings originating from different sources.

    Correlation is conservative. Findings can be correlated when they
    have a strong vulnerability identity match, such as the same
    normalized title or the same CWE combined with compatible
    vulnerability evidence.
    """

    def correlate(
        self,
        findings: Iterable[SecurityFinding],
    ) -> list[SecurityFinding]:
        """
        Correlate related findings and return normalized findings.

        Related findings are merged into the first occurrence while
        preserving information from all contributing sources.
        """

        result: list[SecurityFinding] = []

        for finding in findings:
            match = self._find_match(result, finding)

            if match is None:
                result.append(finding)
            else:
                self._merge_findings(match, finding)

        return result

    def _find_match(
        self,
        existing: list[SecurityFinding],
        candidate: SecurityFinding,
    ) -> SecurityFinding | None:
        for finding in existing:
            if self._are_related(finding, candidate):
                return finding

        return None

    @staticmethod
    def _normalize_title(title: str) -> str:
        """
        Normalize common wording differences in vulnerability titles.

        This allows findings such as:
        - "Content Security Policy (CSP) Header Not Set"
        - "Content Security Policy header is missing"

        to be recognized as the same vulnerability.
        """

        normalized = title.strip().lower()

        replacements = {
            "content security policy": "csp",
            "(csp)": "",
            "header not set": "header missing",
            "header is missing": "header missing",
            "header missing": "header missing",
        }

        for old, new in replacements.items():
            normalized = normalized.replace(old, new)

        return " ".join(normalized.split())

    @staticmethod
    def _are_related(
        first: SecurityFinding,
        second: SecurityFinding,
    ) -> bool:
        """
        Determine whether two findings represent the same issue.

        Correlation does not blindly merge every finding sharing a CWE.
        A shared CWE is used together with vulnerability identity such
        as title, test name, or recognizable security-header evidence.
        """

        first_title = SecurityFindingCorrelator._normalize_title(
            first.title
        )
        second_title = SecurityFindingCorrelator._normalize_title(
            second.title
        )

        # Exact normalized vulnerability identity.
        if first_title == second_title:
            return True

        # Strong match for security-header findings.
        if (
            first.cwe_id == "693"
            and second.cwe_id == "693"
            and SecurityFindingCorrelator._is_csp_finding(first)
            and SecurityFindingCorrelator._is_csp_finding(second)
        ):
            return True

        # Same CWE + same test identity.
        if (
            first.cwe_id
            and second.cwe_id
            and first.cwe_id == second.cwe_id
            and first.test_name
            and second.test_name
            and first.test_name == second.test_name
        ):
            return True

        # Same CWE + same normalized endpoint.
        if (
            first.cwe_id
            and second.cwe_id
            and first.cwe_id == second.cwe_id
        ):
            first_endpoint = (
                first.endpoint.rstrip("/")
                if first.endpoint
                else None
            )
            second_endpoint = (
                second.endpoint.rstrip("/")
                if second.endpoint
                else None
            )

            if (
                first_endpoint
                and second_endpoint
                and first_endpoint == second_endpoint
            ):
                return True

        return False

    @staticmethod
    def _is_csp_finding(
        finding: SecurityFinding,
    ) -> bool:
        """Identify Content Security Policy findings."""

        searchable_text = " ".join(
            [
                finding.title,
                finding.description,
                finding.evidence or "",
                finding.remediation or "",
                finding.test_name or "",
            ]
        ).lower()

        return (
            "content security policy" in searchable_text
            or "content-security-policy" in searchable_text
            or "csp" in searchable_text
        )

    @staticmethod
    def _merge_findings(
        target: SecurityFinding,
        incoming: SecurityFinding,
    ) -> None:
        """Merge information from a related finding."""

        sources = list(target.sources)

        if target.source not in sources:
            sources.append(target.source)

        if incoming.source not in sources:
            sources.append(incoming.source)

        # Include any sources already carried by the incoming finding.
        for source in incoming.sources:
            if source not in sources:
                sources.append(source)

        target.sources = sources
        target.source_count = len(sources)

        if incoming.confidence > target.confidence:
            target.confidence = incoming.confidence

        severity_order = {
            "informational": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        if (
            severity_order[incoming.severity.value]
            > severity_order[target.severity.value]
        ):
            target.severity = incoming.severity

        if not target.description and incoming.description:
            target.description = incoming.description

        if not target.endpoint and incoming.endpoint:
            target.endpoint = incoming.endpoint

        if not target.evidence and incoming.evidence:
            target.evidence = incoming.evidence

        if not target.remediation and incoming.remediation:
            target.remediation = incoming.remediation

        if not target.cwe_id and incoming.cwe_id:
            target.cwe_id = incoming.cwe_id

        if not target.wasc_id and incoming.wasc_id:
            target.wasc_id = incoming.wasc_id

        if not target.test_name and incoming.test_name:
            target.test_name = incoming.test_name


# Backward-compatible names used by existing tests and callers.
FindingCorrelator = SecurityFindingCorrelator