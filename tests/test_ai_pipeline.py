from __future__ import annotations

from pathlib import Path

from framework.ai.collectors import (
    ApiResultCollector,
    UiResultCollector,
    ZapFindingCollector,
)
from framework.ai.correlator import FindingCorrelator
from framework.ai.factory import TriageProviderFactory
from framework.ai.report_generator import AISecurityReportGenerator
from framework.ai.service import SecurityTriageService


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
AI_REPORT_PATH = REPORTS_DIR / "ai-security-assessment.md"


def test_end_to_end_ai_security_pipeline() -> None:
    """
    Verify the complete AI-aware security workflow:

    ZAP/API/UI findings
        -> collection
        -> correlation
        -> AI triage
        -> executive report generation
        -> Markdown report artifact
    """

    # ---------------------------------------------------------
    # 1. Collect findings from all security sources
    # ---------------------------------------------------------

    zap_findings = ZapFindingCollector(
        REPORTS_DIR / "zap-report.json"
    ).collect()

    api_findings = ApiResultCollector(
        REPORTS_DIR / "api-security-findings.json"
    ).collect()

    ui_findings = UiResultCollector(
        REPORTS_DIR / "ui-security-findings.json"
    ).collect()

    findings = [
        *zap_findings,
        *api_findings,
        *ui_findings,
    ]

    assert findings, "No security findings were collected."

    # ---------------------------------------------------------
    # 2. Correlate findings across sources
    # ---------------------------------------------------------

    correlator = FindingCorrelator()
    correlated_findings = correlator.correlate(findings)

    assert correlated_findings, (
        "No correlated findings were produced."
    )

    # ---------------------------------------------------------
    # 3. Create the configured AI provider
    # ---------------------------------------------------------

    provider = TriageProviderFactory.create()

    # ---------------------------------------------------------
    # 4. Run AI security triage
    # ---------------------------------------------------------

    service = SecurityTriageService(provider)

    triage_results = service.triage_findings(
        correlated_findings
    )

    assert triage_results, (
        "AI triage produced no results."
    )

    assert len(triage_results) == len(correlated_findings), (
        "AI triage result count does not match the number "
        "of correlated findings."
    )

    # ---------------------------------------------------------
    # 5. Generate executive security assessment
    # ---------------------------------------------------------

    generator = AISecurityReportGenerator(provider)

    report = generator.generate_markdown_report(
        correlated_findings
    )

    assert report
    assert "# Executive Security Assessment" in report

    # The report should identify the active AI provider.
    assert "Provider:" in report

    # ---------------------------------------------------------
    # 6. Save the AI assessment as a Markdown artifact
    # ---------------------------------------------------------

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    AI_REPORT_PATH.write_text(
        report,
        encoding="utf-8",
    )

    assert AI_REPORT_PATH.exists()
    assert AI_REPORT_PATH.stat().st_size > 0