from __future__ import annotations

from framework.ai.providers import (
    DeterministicTriageProvider,
    OpenAITriageProvider,
    SecurityTriageProvider,
)
from framework.config.settings import settings


class TriageProviderFactory:
    """Create the configured security triage provider."""

    @staticmethod
    def create(
        provider_name: str | None = None,
    ) -> SecurityTriageProvider:
        """
        Create a triage provider.

        Supported providers:
        - deterministic
        - openai
        """

        provider = (
            provider_name or settings.AI_PROVIDER
        ).strip().lower()

        if provider == "deterministic":
            return DeterministicTriageProvider()

        if provider == "openai":
            return OpenAITriageProvider()

        raise ValueError(
            f"Unsupported AI provider: {provider!r}. "
            "Supported providers are: "
            "deterministic, openai."
        )