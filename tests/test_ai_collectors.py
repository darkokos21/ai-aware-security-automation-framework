import json
from pathlib import Path

from framework.ai.collectors import ZapFindingCollector
from framework.ai.models import FindingSeverity, FindingSource
from framework.ai.test_results import SecurityTestResultCollector

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_zap_collector_loads_findings() -> None:
    collector = ZapFindingCollector(
        FIXTURES_DIR / "zap-report.json"
    )

    findings = collector.collect()

    assert len(findings) == 259
    assert all(
        finding.source == FindingSource.ZAP
        for finding in findings
    )


def test_zap_collector_loads_native_zap_json_report(
    tmp_path: Path,
) -> None:
    """
    zap-baseline.py -J writes ZAP's native report layout:
    site -> alerts -> instances. Every instance becomes one finding.
    """

    native_report = {
        "@programName": "ZAP",
        "@version": "2.16.0",
        "site": [
            {
                "@name": "http://juice-shop:3000",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "name": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "confidence": "3",
                        "riskdesc": "Medium (High)",
                        "desc": "<p>CSP is an added layer of security.</p>",
                        "instances": [
                            {
                                "uri": "http://juice-shop:3000/",
                                "method": "GET",
                                "evidence": "",
                            },
                            {
                                "uri": "http://juice-shop:3000/robots.txt",
                                "method": "GET",
                                "evidence": "",
                            },
                        ],
                        "count": "2",
                        "solution": "<p>Configure the CSP header.</p>",
                        "reference": "<p>https://example.invalid/csp</p>",
                        "cweid": "693",
                        "wascid": "15",
                    },
                    {
                        "pluginid": "10096",
                        "alert": "Timestamp Disclosure - Unix",
                        "name": "Timestamp Disclosure - Unix",
                        "riskcode": "1",
                        "confidence": "1",
                        "riskdesc": "Low (Low)",
                        "desc": "<p>A timestamp was disclosed.</p>",
                        "instances": [
                            {
                                "uri": "http://juice-shop:3000/main.js",
                                "method": "GET",
                                "evidence": "1734567890",
                            }
                        ],
                        "count": "1",
                        "solution": "",
                        "reference": "",
                        "cweid": "497",
                        "wascid": "13",
                    },
                ],
            }
        ],
    }

    report_path = tmp_path / "zap-report.json"
    report_path.write_text(
        json.dumps(native_report),
        encoding="utf-8",
    )

    findings = ZapFindingCollector(report_path).collect()

    assert len(findings) == 3
    assert all(
        finding.source == FindingSource.ZAP
        for finding in findings
    )

    csp = findings[0]

    assert csp.title == "Content Security Policy (CSP) Header Not Set"
    assert csp.severity == FindingSeverity.MEDIUM
    assert csp.confidence == 0.95
    assert csp.endpoint == "http://juice-shop:3000/"
    assert csp.description == "CSP is an added layer of security."
    assert csp.remediation == "Configure the CSP header."
    assert csp.cwe_id == "693"
    assert csp.wasc_id == "15"

    assert findings[1].endpoint == "http://juice-shop:3000/robots.txt"

    timestamp = findings[2]

    assert timestamp.severity == FindingSeverity.LOW
    assert timestamp.confidence == 0.50
    assert timestamp.evidence == "1734567890"
    assert timestamp.remediation is None


def test_api_result_collector_loads_findings() -> None:
    collector = SecurityTestResultCollector(
        FIXTURES_DIR / "api-security-findings.json",
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
        FIXTURES_DIR / "ui-security-findings.json",
        FindingSource.UI,
    )

    findings = collector.collect()

    assert len(findings) == 2
    assert all(
        finding.source == FindingSource.UI
        for finding in findings
    )
