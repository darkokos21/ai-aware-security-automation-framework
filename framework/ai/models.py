from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class FindingSource(StrEnum):
    """Source of a security finding."""

    API = "api"
    UI = "ui"
    ZAP = "zap"


class FindingSeverity(StrEnum):
    """Normalized security finding severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class TriagePriority(StrEnum):
    """AI-assigned remediation priority."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class SecurityFinding(BaseModel):
    """Normalized representation of a security finding."""

    title: str = Field(min_length=1)
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFORMATIONAL
    source: FindingSource
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
    )

    endpoint: str | None = None
    evidence: str | None = None
    remediation: str | None = None

    cwe_id: str | None = None
    wasc_id: str | None = None

    test_name: str | None = None

    sources: list[FindingSource] = Field(
        default_factory=list,
    )

    source_count: int = 1

    @property
    def fingerprint(self) -> str:
        """Return a stable identifier used for finding correlation."""

        normalized_title = self.title.strip().lower()

        normalized_endpoint = (
            self.endpoint.strip().lower()
            if self.endpoint
            else ""
        )

        return (
            f"{normalized_title}|"
            f"{normalized_endpoint}"
        )


class TriageResult(BaseModel):
    """AI-generated security triage result."""

    finding: SecurityFinding

    priority: TriagePriority

    severity: FindingSeverity

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    explanation: str = Field(
        min_length=1,
    )

    impact: str = Field(
        min_length=1,
    )

    remediation: str = Field(
        min_length=1,
    )

    rationale: str = Field(
        min_length=1,
    )