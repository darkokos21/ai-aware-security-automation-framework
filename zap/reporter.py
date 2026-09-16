from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from zap.models import ZapAlert


class ZapReporter:
    """Generate machine-readable and human-readable ZAP reports."""

    def __init__(
        self,
        output_directory: str = "reports",
    ) -> None:
        self.output_directory = Path(output_directory)

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def write_json(
        self,
        alerts: list[ZapAlert],
        filename: str = "zap-report.json",
    ) -> Path:
        """Write normalized ZAP findings to JSON."""

        output = self.output_directory / filename

        data = [
            {
                "name": alert.name,
                "risk": alert.risk,
                "confidence": alert.confidence,
                "url": alert.url,
                "description": alert.description,
                "solution": alert.solution,
                "reference": alert.reference,
                "cwe_id": alert.cwe_id,
                "wasc_id": alert.wasc_id,
            }
            for alert in alerts
        ]

        output.write_text(
            json.dumps(
                data,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return output

    def write_markdown(
        self,
        alerts: list[ZapAlert],
        filename: str = "zap-report.md",
    ) -> Path:
        """Write a human-readable security report."""

        output = self.output_directory / filename

        summary = self._build_summary(alerts)
        findings = self._group_findings(alerts)

        lines = [
            "# OWASP ZAP Security Report",
            "",
            "## Scan Summary",
            "",
            f"- **Total raw alerts:** {len(alerts)}",
            f"- **Unique findings:** {len(findings)}",
            "",
            "### Risk Distribution",
            "",
            "| Risk | Count |",
            "|---|---:|",
        ]

        for risk in (
            "High",
            "Medium",
            "Low",
            "Informational",
        ):
            lines.append(
                f"| {risk} | "
                f"{summary.get(risk, 0)} |"
            )

        lines.extend(
            [
                "",
                "## Findings",
                "",
            ]
        )

        if not findings:
            lines.extend(
                [
                    "No security findings were reported.",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "| Risk | Finding | CWE | Affected URLs |",
                    "|---|---|---|---:|",
                ]
            )

            sorted_findings = sorted(
                findings.values(),
                key=lambda item: (
                    -item["risk_level"],
                    item["name"],
                ),
            )

            for finding in sorted_findings:
                lines.append(
                    f"| {finding['risk']} | "
                    f"{finding['name']} | "
                    f"{finding['cwe_id'] or '-'} | "
                    f"{len(finding['urls'])} |"
                )

            lines.extend(
                [
                    "",
                    "## Finding Details",
                    "",
                ]
            )

            for finding in sorted_findings:
                lines.extend(
                    [
                        f"### {finding['name']}",
                        "",
                        f"- **Risk:** {finding['risk']}",
                        f"- **Confidence:** {finding['confidence']}",
                        f"- **CWE:** {finding['cwe_id'] or 'N/A'}",
                        f"- **Affected URLs:** {len(finding['urls'])}",
                        "",
                        "**Description**",
                        "",
                        finding["description"] or "N/A",
                        "",
                        "**Recommended Solution**",
                        "",
                        finding["solution"] or "N/A",
                        "",
                    ]
                )

                if finding["reference"]:
                    lines.extend(
                        [
                            f"**Reference:** {finding['reference']}",
                            "",
                        ]
                    )

                lines.append("**Affected URLs**")

                for url in sorted(finding["urls"]):
                    lines.append(
                        f"- `{url}`"
                    )

                lines.append("")

        output.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

        return output

    def write_summary(
        self,
        alerts: list[ZapAlert],
        filename: str = "zap-summary.json",
    ) -> Path:
        """Write a compact machine-readable scan summary."""

        output = self.output_directory / filename

        findings = self._group_findings(alerts)

        summary = {
            "total_alerts": len(alerts),
            "unique_findings": len(findings),
            "risk_counts": self._build_summary(alerts),
            "findings": [
                {
                    "name": finding["name"],
                    "risk": finding["risk"],
                    "confidence": finding["confidence"],
                    "cwe_id": finding["cwe_id"],
                    "affected_url_count": len(
                        finding["urls"]
                    ),
                }
                for finding in sorted(
                    findings.values(),
                    key=lambda item: (
                        -item["risk_level"],
                        item["name"],
                    ),
                )
            ],
        }

        output.write_text(
            json.dumps(
                summary,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return output

    @staticmethod
    def _build_summary(
        alerts: list[ZapAlert],
    ) -> Counter[str]:
        """Count alerts by risk level."""

        return Counter(
            alert.risk
            for alert in alerts
        )

    @staticmethod
    def _group_findings(
        alerts: list[ZapAlert],
    ) -> dict[
        tuple[str, str, str],
        dict,
    ]:
        """
        Group alerts by finding type.

        Multiple affected URLs are retained under the same finding.
        """

        findings: dict[
            tuple[str, str, str],
            dict,
        ] = defaultdict(
            lambda: {
                "name": "",
                "risk": "",
                "risk_level": 0,
                "confidence": "",
                "cwe_id": "",
                "description": "",
                "solution": "",
                "reference": "",
                "urls": set(),
            }
        )

        for alert in alerts:
            key = alert.finding_key

            finding = findings[key]

            finding["name"] = alert.name
            finding["risk"] = alert.risk
            finding["risk_level"] = alert.risk_level
            finding["confidence"] = alert.confidence
            finding["cwe_id"] = alert.cwe_id
            finding["description"] = alert.description
            finding["solution"] = alert.solution
            finding["reference"] = alert.reference

            if alert.url:
                finding["urls"].add(alert.url)

        return findings