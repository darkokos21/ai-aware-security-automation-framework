from framework.ai.collectors import ZapFindingCollector
from framework.ai.correlator import FindingCorrelator


def test_zap_findings_are_correlated() -> None:
    collector = ZapFindingCollector(
        "reports/zap-report.json"
    )

    findings = collector.collect()

    correlator = FindingCorrelator()

    correlated = correlator.correlate(
        findings
    )

    assert len(findings) == 259
    assert len(correlated) == 4