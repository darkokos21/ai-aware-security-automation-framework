from unittest.mock import MagicMock, patch

import pytest

from framework.ai.factory import TriageProviderFactory
from framework.ai.providers import (
    DeterministicTriageProvider,
    OpenAITriageProvider,
)


def test_factory_creates_deterministic_provider() -> None:
    provider = TriageProviderFactory.create(
        "deterministic"
    )

    assert isinstance(
        provider,
        DeterministicTriageProvider,
    )


def test_factory_creates_openai_provider() -> None:
    with patch(
        "framework.ai.factory.OpenAITriageProvider"
    ) as provider_class:
        provider_class.return_value = MagicMock(
            spec=OpenAITriageProvider
        )

        provider = TriageProviderFactory.create(
            "openai"
        )

        provider_class.assert_called_once()
        assert provider is provider_class.return_value


def test_factory_rejects_unknown_provider() -> None:
    with pytest.raises(
        ValueError,
        match="Unsupported AI provider",
    ):
        TriageProviderFactory.create(
            "unknown-provider"
        )