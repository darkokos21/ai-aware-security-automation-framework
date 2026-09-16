from framework.ai.collectors import ZapFindingCollector
from framework.ai.models import FindingSource
from framework.ai.test_results import SecurityTestResultCollector


def test_zap_collector_loads_findings() -> None:
    collector = ZapFindingCollector(
        "reports/zap-report.json"
    )

    findings = collector.collect()

    assert len(findings) == 259
    assert all(
        finding.source == FindingSource.ZAP
        for finding in findings
    )


def test_api_result_collector_loads_findings() -> None:
    collector = SecurityTestResultCollector(
        "reports/api-security-findings.json",
        FindingSource.API,
    )

    findings = collector.collect()

    assert len(findings) == 5
    assert all(
        finding.source == FindingSource.API
        for finding in findings
    )


def test_ui_result_collector_loads_findings() -> None:
    collector = SecurityTestResultCollector(
        "reports/ui-security-findings.json",
        FindingSource.UI,
    )

    findings = collector.collect()

    assert len(findings) == 2
    assert all(
        finding.source == FindingSource.UI
        for finding in findings
    )