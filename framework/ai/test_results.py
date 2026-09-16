from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from framework.ai.models import (
    FindingSeverity,
    FindingSource,
    SecurityFinding,
)


class SecurityTestResultCollector:
    """Collect security findings from a JSON test-result file."""

    def __init__(
        self,
        report_path: str | Path,
        source: FindingSource,
    ) -> None:
        self.report_path = Path(report_path)
        self.source = source

    def collect(self) -> list[SecurityFinding]:
        """Load and normalize failed security test results."""

        if not self.report_path.exists():
            raise FileNotFoundError(
                f"Test result report not found: "
                f"{self.report_path}"
            )

        with self.report_path.open(
            "r",
            encoding="utf-8",
        ) as report_file:
            data: Any = json.load(report_file)

        if not isinstance(data, list):
            raise ValueError(
                "Invalid test result format: "
                "expected a list of findings."
            )

        return [
            self._normalize_finding(result)
            for result in data
            if isinstance(result, dict)
        ]

    def _normalize_finding(
        self,
        result: dict[str, Any],
    ) -> SecurityFinding:
        return SecurityFinding(
            title=str(
                result.get(
                    "title",
                    "Unknown security test failure",
                )
            ),
            description=str(
                result.get(
                    "description",
                    "",
                )
            ),
            severity=self._map_severity(
                result.get("severity")
            ),
            source=self.source,
            confidence=self._map_confidence(
                result.get("confidence")
            ),
            endpoint=(
                str(result["endpoint"])
                if result.get("endpoint")
                else None
            ),
            evidence=(
                str(result["evidence"])
                if result.get("evidence")
                else None
            ),
            remediation=(
                str(result["remediation"])
                if result.get("remediation")
                else None
            ),
            cwe_id=(
                str(result["cwe_id"])
                if result.get("cwe_id")
                else None
            ),
            wasc_id=(
                str(result["wasc_id"])
                if result.get("wasc_id")
                else None
            ),
            test_name=(
                str(result["test_name"])
                if result.get("test_name")
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
            return 1.0

        try:
            numeric = float(confidence)
        except (TypeError, ValueError):
            return 1.0

        if numeric > 1:
            numeric /= 100

        return max(
            0.0,
            min(1.0, numeric),
        )