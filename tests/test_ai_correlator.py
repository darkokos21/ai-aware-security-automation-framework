from pathlib import Path

from framework.ai.collectors import ZapFindingCollector
from framework.ai.correlator import FindingCorrelator

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_zap_findings_are_correlated() -> None:
    collector = ZapFindingCollector(
        FIXTURES_DIR / "zap-report.json"
    )

    findings = collector.collect()

    correlator = FindingCorrelator()

    correlated = correlator.correlate(
        findings
    )

    assert len(findings) == 259
    assert len(correlated) == 4
