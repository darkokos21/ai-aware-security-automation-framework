from unittest.mock import MagicMock

from framework.ai.models import (
    FindingSeverity,
    FindingSource,
    SecurityFinding,
    TriagePriority,
    TriageResult,
)
from framework.ai.providers import (
    DeterministicTriageProvider,
    OpenAITriageProvider,
    SecurityTriageProvider,
)


def _create_finding() -> SecurityFinding:
    return SecurityFinding(
        title="SQL injection authentication bypass",
        description=(
            "A SQL injection payload successfully "
            "authenticated against the login endpoint."
        ),
        severity=FindingSeverity.CRITICAL,
        source=FindingSource.API,
        confidence=1.0,
        endpoint="/rest/user/login",
        evidence="' OR 1=1--",
        remediation=(
            "Use parameterized queries or prepared statements."
        ),
        cwe_id="89",
        sources=[FindingSource.API],
        source_count=1,
    )


def _create_triage_result(
    finding: SecurityFinding,
) -> TriageResult:
    return TriageResult(
        finding=finding,
        priority=TriagePriority.CRITICAL,
        severity=FindingSeverity.CRITICAL,
        confidence=1.0,
        explanation="The finding indicates SQL injection.",
        impact=(
            "An attacker may manipulate database queries."
        ),
        remediation=(
            "Use parameterized queries or prepared statements."
        ),
        rationale=(
            "The finding has critical severity and direct evidence."
        ),
    )


def test_deterministic_provider_implements_provider_interface() -> None:
    provider = DeterministicTriageProvider()

    assert isinstance(
        provider,
        SecurityTriageProvider,
    )


def test_deterministic_provider_returns_triage_result() -> None:
    finding = _create_finding()

    provider = DeterministicTriageProvider()

    result = provider.triage(finding)

    assert result.finding == finding
    assert result.severity == FindingSeverity.CRITICAL
    assert result.priority == TriagePriority.CRITICAL
    assert result.confidence == 1.0
    assert result.explanation
    assert result.impact
    assert result.remediation
    assert result.rationale


def test_openai_provider_implements_provider_interface() -> None:
    client = MagicMock()

    provider = OpenAITriageProvider(
        api_key="test-key",
        client=client,
    )

    assert isinstance(
        provider,
        SecurityTriageProvider,
    )


def test_openai_provider_returns_structured_triage_result() -> None:
    finding = _create_finding()
    expected_result = _create_triage_result(finding)

    parsed_content = MagicMock()
    parsed_content.type = "output_text"
    parsed_content.parsed = expected_result

    message = MagicMock()
    message.type = "message"
    message.content = [parsed_content]

    response = MagicMock()
    response.output = [message]

    client = MagicMock()
    client.responses.parse.return_value = response

    provider = OpenAITriageProvider(
        api_key="test-key",
        model="test-model",
        client=client,
    )

    result = provider.triage(finding)

    assert result.finding == finding
    assert result.priority == TriagePriority.CRITICAL
    assert result.severity == FindingSeverity.CRITICAL
    assert result.confidence == 1.0

    client.responses.parse.assert_called_once()

    call_kwargs = (
        client.responses.parse.call_args.kwargs
    )

    assert call_kwargs["model"] == "test-model"
    assert call_kwargs["text_format"] == TriageResult