from framework.ai.collectors import ZapFindingCollector
from framework.ai.correlator import FindingCorrelator
from framework.ai.models import FindingSource
from framework.ai.test_results import SecurityTestResultCollector


def _collect_all_findings():
    zap_findings = ZapFindingCollector(
        "reports/zap-report.json"
    ).collect()

    api_findings = SecurityTestResultCollector(
        "reports/api-security-findings.json",
        FindingSource.API,
    ).collect()

    ui_findings = SecurityTestResultCollector(
        "reports/ui-security-findings.json",
        FindingSource.UI,
    ).collect()

    return (
        zap_findings
        + api_findings
        + ui_findings
    )


def test_cross_source_findings_are_correlated() -> None:
    findings = _collect_all_findings()

    correlator = FindingCorrelator()
    correlated = correlator.correlate(findings)

    assert len(findings) == 266

    csp_findings = [
        finding
        for finding in correlated
        if finding.cwe_id == "693"
        and "content security policy"
        in finding.title.lower()
    ]

    assert len(csp_findings) == 1

    csp = csp_findings[0]

    assert csp.source_count == 3

    assert set(csp.sources) == {
        FindingSource.API,
        FindingSource.UI,
        FindingSource.ZAP,
    }


def test_same_cwe_does_not_automatically_merge_different_findings() -> None:
    findings = _collect_all_findings()

    correlator = FindingCorrelator()
    correlated = correlator.correlate(findings)

    cwe_693_findings = [
        finding
        for finding in correlated
        if finding.cwe_id == "693"
    ]

    titles = {
        finding.title.lower()
        for finding in cwe_693_findings
    }

    assert len(cwe_693_findings) >= 2
    assert any(
        "content security policy" in title
        for title in titles
    )
    assert any(
        "referrer" in title
        for title in titles
    )