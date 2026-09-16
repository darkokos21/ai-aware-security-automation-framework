from __future__ import annotations

from abc import ABC, abstractmethod

from openai import OpenAI

from framework.ai.models import SecurityFinding, TriageResult
from framework.ai.triage import SecurityTriageEngine
from framework.config.settings import settings
from framework.logging.logger import get_logger


class AIProvider(ABC):
    """
    Common interface for all AI providers used by the framework.

    A provider must support:
    - Security finding triage.
    - Executive security report generation.
    """

    @abstractmethod
    def triage(
        self,
        finding: SecurityFinding,
    ) -> TriageResult:
        """Analyze one security finding."""
        raise NotImplementedError

    @abstractmethod
    def generate_report(
        self,
        prompt: str,
    ) -> str:
        """Generate a Markdown executive security report."""
        raise NotImplementedError


class DeterministicAIProvider(AIProvider):
    """
    Offline deterministic provider.

    Used for:
    - Unit tests.
    - CI/CD.
    - Users without an OpenAI API key.
    """

    def __init__(
        self,
        engine: SecurityTriageEngine | None = None,
    ) -> None:
        self.engine = engine or SecurityTriageEngine()

    def triage(
        self,
        finding: SecurityFinding,
    ) -> TriageResult:
        return self.engine.triage(finding)

    def generate_report(
        self,
        prompt: str,
    ) -> str:
        return (
            "# Executive Security Assessment\n\n"
            "Deterministic provider is enabled.\n\n"
            "This placeholder report confirms that the AI reporting "
            "pipeline is functioning correctly.\n\n"
            "When an OpenAI API key is configured, this report will "
            "contain a complete AI-generated executive assessment, "
            "risk summary, and remediation roadmap."
        )


class OpenAIProvider(AIProvider):
    """
    OpenAI-backed provider.

    Supports:
    - Structured security triage.
    - Executive report generation.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        client: OpenAI | None = None,
    ) -> None:
        self.api_key = api_key or settings.OPENAI_API_KEY
        self.model = model or settings.AI_MODEL
        self.logger = get_logger(self.__class__.__name__)

        if client is not None:
            self.client = client
            return

        if not self.api_key:
            raise ValueError(
                "OPENAI_API_KEY is required when using OpenAIProvider."
            )

        self.client = OpenAI(api_key=self.api_key)

    def triage(
        self,
        finding: SecurityFinding,
    ) -> TriageResult:
        """Send a security finding to OpenAI for structured triage."""

        prompt = self._build_triage_prompt(finding)

        self.logger.info(
            "Sending security finding to OpenAI model: %s",
            self.model,
        )

        response = self.client.responses.parse(
            model=self.model,
            input=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior application security engineer "
                        "performing vulnerability triage. Analyze only the "
                        "supplied evidence. Never invent evidence or exploitability."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            text_format=TriageResult,
        )

        parsed_result = self._extract_triage_result(response)

        # Preserve our normalized finding object.
        parsed_result.finding = finding

        return parsed_result

    def generate_report(
        self,
        prompt: str,
    ) -> str:
        """
        Generate a Markdown executive security report.
        """

        self.logger.info(
            "Generating AI executive security report with %s",
            self.model,
        )

        response = self.client.responses.create(
            model=self.model,
            input=prompt,
            temperature=0.2,
        )

        return response.output_text

    @staticmethod
    def _build_triage_prompt(
        finding: SecurityFinding,
    ) -> str:
        return (
            "Analyze the following normalized security finding.\n\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"Severity: {finding.severity.value}\n"
            f"Source: {finding.source.value}\n"
            f"Confidence: {finding.confidence}\n"
            f"Endpoint: {finding.endpoint or 'N/A'}\n"
            f"Evidence: {finding.evidence or 'N/A'}\n"
            f"Existing remediation: {finding.remediation or 'N/A'}\n"
            f"CWE: {finding.cwe_id or 'N/A'}\n"
            f"WASC: {finding.wasc_id or 'N/A'}\n"
            f"Test name: {finding.test_name or 'N/A'}\n"
            f"Detected sources: "
            f"{', '.join(source.value for source in finding.sources) if finding.sources else finding.source.value}\n"
            f"Source count: {finding.source_count}\n\n"
            "Produce:\n"
            "1. A remediation priority.\n"
            "2. A normalized severity.\n"
            "3. A confidence score between 0 and 1.\n"
            "4. A concise explanation.\n"
            "5. A realistic impact statement.\n"
            "6. A remediation recommendation.\n"
            "7. A rationale for the assigned priority."
        )

    @staticmethod
    def _extract_triage_result(
        response: object,
    ) -> TriageResult:
        output = getattr(response, "output", None)

        if not output:
            raise ValueError("OpenAI returned no output.")

        for output_item in output:
            if getattr(output_item, "type", None) != "message":
                continue

            for content_item in getattr(output_item, "content", []):
                if getattr(content_item, "type", None) != "output_text":
                    continue

                parsed = getattr(content_item, "parsed", None)

                if isinstance(parsed, TriageResult):
                    return parsed

        raise ValueError(
            "OpenAI response did not contain a valid structured TriageResult."
        )


# ---------------------------------------------------------------------
# Backwards compatibility aliases
# ---------------------------------------------------------------------

# Existing tests and imports continue working.
SecurityTriageProvider = AIProvider
DeterministicTriageProvider = DeterministicAIProvider
OpenAITriageProvider = OpenAIProvider