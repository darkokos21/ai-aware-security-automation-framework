from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from framework.ai.models import (
    FindingSeverity,
    FindingSource,
    SecurityFinding,
)


class ZapFindingCollector:
    """Collect normalized findings from a ZAP JSON report."""

    def __init__(self, report_path: str | Path) -> None:
        self.report_path = Path(report_path)

    def collect(self) -> list[SecurityFinding]:
        """Load and normalize findings from the ZAP report."""

        if not self.report_path.exists():
            raise FileNotFoundError(
                f"ZAP report not found: {self.report_path}"
            )

        with self.report_path.open(
            "r",
            encoding="utf-8",
        ) as report_file:
            data: Any = json.load(report_file)

        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = data.get("findings", [])
        else:
            raise ValueError(
                "Invalid ZAP report format: "
                "expected a list or an object containing "
                "'findings'."
            )

        if not isinstance(findings, list):
            raise ValueError(
                "Invalid ZAP report format: "
                "'findings' must be a list."
            )

        return [
            self._normalize_finding(finding)
            for finding in findings
            if isinstance(finding, dict)
        ]

    @staticmethod
    def _normalize_finding(
        finding: dict[str, Any],
    ) -> SecurityFinding:
        return SecurityFinding(
            title=str(
                finding.get(
                    "name",
                    "Unknown ZAP finding",
                )
            ),
            description=str(
                finding.get(
                    "description",
                    "",
                )
            ),
            severity=ZapFindingCollector._map_severity(
                finding.get("risk")
            ),
            source=FindingSource.ZAP,
            confidence=ZapFindingCollector._map_confidence(
                finding.get("confidence")
            ),
            endpoint=(
                str(finding["url"])
                if finding.get("url")
                else None
            ),
            evidence=(
                str(finding["evidence"])
                if finding.get("evidence")
                else None
            ),
            remediation=(
                str(finding["solution"])
                if finding.get("solution")
                else None
            ),
            cwe_id=(
                str(finding["cwe_id"])
                if finding.get("cwe_id")
                else None
            ),
            wasc_id=(
                str(finding["wasc_id"])
                if finding.get("wasc_id")
                else None
            ),
        )

    @staticmethod
    def _map_severity(
        risk: Any,
    ) -> FindingSeverity:
        normalized = str(risk or "").strip().lower()

        mapping = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "informational": FindingSeverity.INFORMATIONAL,
            "info": FindingSeverity.INFORMATIONAL,
        }

        return mapping.get(
            normalized,
            FindingSeverity.INFORMATIONAL,
        )

    @staticmethod
    def _map_confidence(
        confidence: Any,
    ) -> float:
        normalized = str(
            confidence or ""
        ).strip().lower()

        mapping = {
            "high": 0.95,
            "medium": 0.75,
            "low": 0.50,
            "false positive": 0.10,
        }

        if normalized in mapping:
            return mapping[normalized]

        try:
            numeric = float(confidence)
        except (TypeError, ValueError):
            return 0.50

        if numeric > 1:
            numeric /= 100

        return max(
            0.0,
            min(1.0, numeric),
        )


class ApiResultCollector:
    """Collect normalized security findings from API test results."""

    def __init__(self, report_path: str | Path) -> None:
        self.report_path = Path(report_path)

    def collect(self) -> list[SecurityFinding]:
        """Load and normalize findings from an API result file."""

        data = self._load_json()
        findings = self._extract_findings(data)

        return [
            self._normalize_finding(finding)
            for finding in findings
            if isinstance(finding, dict)
        ]

    def _load_json(self) -> Any:
        if not self.report_path.exists():
            raise FileNotFoundError(
                f"API result report not found: {self.report_path}"
            )

        with self.report_path.open(
            "r",
            encoding="utf-8",
        ) as report_file:
            return json.load(report_file)

    @staticmethod
    def _extract_findings(
        data: Any,
    ) -> list[Any]:
        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            findings = data.get("findings", [])

            if isinstance(findings, list):
                return findings

            raise ValueError(
                "Invalid API result format: "
                "'findings' must be a list."
            )

        raise ValueError(
            "Invalid API result format: "
            "expected a list or an object containing "
            "'findings'."
        )

    @staticmethod
    def _normalize_finding(
        finding: dict[str, Any],
    ) -> SecurityFinding:
        return SecurityFinding(
            title=str(
                finding.get(
                    "title",
                    finding.get(
                        "name",
                        "Unknown API security finding",
                    ),
                )
            ),
            description=str(
                finding.get(
                    "description",
                    "",
                )
            ),
            severity=ApiResultCollector._map_severity(
                finding.get(
                    "severity",
                    finding.get("risk"),
                )
            ),
            source=FindingSource.API,
            confidence=ApiResultCollector._map_confidence(
                finding.get("confidence")
            ),
            endpoint=(
                str(finding["endpoint"])
                if finding.get("endpoint")
                else (
                    str(finding["url"])
                    if finding.get("url")
                    else None
                )
            ),
            evidence=(
                str(finding["evidence"])
                if finding.get("evidence")
                else None
            ),
            remediation=(
                str(
                    finding.get(
                        "remediation",
                        finding.get("solution"),
                    )
                )
                if finding.get(
                    "remediation",
                    finding.get("solution"),
                )
                else None
            ),
            cwe_id=(
                str(finding["cwe_id"])
                if finding.get("cwe_id")
                else None
            ),
            wasc_id=(
                str(finding["wasc_id"])
                if finding.get("wasc_id")
                else None
            ),
            test_name=(
                str(finding["test_name"])
                if finding.get("test_name")
                else None
            ),
        )

    @staticmethod
    def _map_severity(
        severity: Any,
    ) -> FindingSeverity:
        normalized = str(
            severity or ""
        ).strip().lower()

        mapping = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "informational": FindingSeverity.INFORMATIONAL,
            "info": FindingSeverity.INFORMATIONAL,
        }

        return mapping.get(
            normalized,
            FindingSeverity.INFORMATIONAL,
        )

    @staticmethod
    def _map_confidence(
        confidence: Any,
    ) -> float:
        if confidence is None:
            return 0.50

        normalized = str(
            confidence
        ).strip().lower()

        mapping = {
            "high": 0.95,
            "medium": 0.75,
            "low": 0.50,
            "false positive": 0.10,
        }

        if normalized in mapping:
            return mapping[normalized]

        try:
            numeric = float(confidence)
        except (TypeError, ValueError):
            return 0.50

        if numeric > 1:
            numeric /= 100

        return max(
            0.0,
            min(1.0, numeric),
        )


class UiResultCollector:
    """Collect normalized security findings from UI test results."""

    def __init__(self, report_path: str | Path) -> None:
        self.report_path = Path(report_path)

    def collect(self) -> list[SecurityFinding]:
        """Load and normalize findings from a UI result file."""

        data = self._load_json()
        findings = self._extract_findings(data)

        return [
            self._normalize_finding(finding)
            for finding in findings
            if isinstance(finding, dict)
        ]

    def _load_json(self) -> Any:
        if not self.report_path.exists():
            raise FileNotFoundError(
                f"UI result report not found: {self.report_path}"
            )

        with self.report_path.open(
            "r",
            encoding="utf-8",
        ) as report_file:
            return json.load(report_file)

    @staticmethod
    def _extract_findings(
        data: Any,
    ) -> list[Any]:
        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            findings = data.get("findings", [])

            if isinstance(findings, list):
                return findings

            raise ValueError(
                "Invalid UI result format: "
                "'findings' must be a list."
            )

        raise ValueError(
            "Invalid UI result format: "
            "expected a list or an object containing "
            "'findings'."
        )

    @staticmethod
    def _normalize_finding(
        finding: dict[str, Any],
    ) -> SecurityFinding:
        return SecurityFinding(
            title=str(
                finding.get(
                    "title",
                    finding.get(
                        "name",
                        "Unknown UI security finding",
                    ),
                )
            ),
            description=str(
                finding.get(
                    "description",
                    "",
                )
            ),
            severity=UiResultCollector._map_severity(
                finding.get(
                    "severity",
                    finding.get("risk"),
                )
            ),
            source=FindingSource.UI,
            confidence=UiResultCollector._map_confidence(
                finding.get("confidence")
            ),
            endpoint=(
                str(finding["endpoint"])
                if finding.get("endpoint")
                else (
                    str(finding["url"])
                    if finding.get("url")
                    else None
                )
            ),
            evidence=(
                str(finding["evidence"])
                if finding.get("evidence")
                else None
            ),
            remediation=(
                str(
                    finding.get(
                        "remediation",
                        finding.get("solution"),
                    )
                )
                if finding.get(
                    "remediation",
                    finding.get("solution"),
                )
                else None
            ),
            cwe_id=(
                str(finding["cwe_id"])
                if finding.get("cwe_id")
                else None
            ),
            wasc_id=(
                str(finding["wasc_id"])
                if finding.get("wasc_id")
                else None
            ),
            test_name=(
                str(finding["test_name"])
                if finding.get("test_name")
                else None
            ),
        )

    @staticmethod
    def _map_severity(
        severity: Any,
    ) -> FindingSeverity:
        normalized = str(
            severity or ""
        ).strip().lower()

        mapping = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "informational": FindingSeverity.INFORMATIONAL,
            "info": FindingSeverity.INFORMATIONAL,
        }

        return mapping.get(
            normalized,
            FindingSeverity.INFORMATIONAL,
        )

    @staticmethod
    def _map_confidence(
        confidence: Any,
    ) -> float:
        if confidence is None:
            return 0.50

        normalized = str(
            confidence
        ).strip().lower()

        mapping = {
            "high": 0.95,
            "medium": 0.75,
            "low": 0.50,
            "false positive": 0.10,
        }

        if normalized in mapping:
            return mapping[normalized]

        try:
            numeric = float(confidence)
        except (TypeError, ValueError):
            return 0.50

        if numeric > 1:
            numeric /= 100

        return max(
            0.0,
            min(1.0, numeric),
        )


class SecurityFindingCollection:
    """Container for findings collected from multiple sources."""

    def __init__(
        self,
        findings: list[SecurityFinding] | None = None,
    ) -> None:
        self.findings = findings or []

    def add(
        self,
        findings: list[SecurityFinding],
    ) -> None:
        """Add findings to the collection."""

        self.findings.extend(findings)

    def all(self) -> list[SecurityFinding]:
        """Return all collected findings."""

        return list(self.findings)

    def count(self) -> int:
        """Return the number of collected findings."""

        return len(self.findings)