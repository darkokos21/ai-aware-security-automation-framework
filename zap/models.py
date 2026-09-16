from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ZapAlert:
    """Normalized OWASP ZAP alert."""

    name: str
    risk: str
    confidence: str
    url: str
    description: str
    solution: str
    reference: str
    cwe_id: str
    wasc_id: str

    @property
    def risk_level(self) -> int:
        """Return a numeric severity level for sorting."""
        levels = {
            "Informational": 0,
            "Low": 1,
            "Medium": 2,
            "High": 3,
        }

        return levels.get(self.risk, 0)

    @property
    def finding_key(self) -> tuple[str, str, str]:
        """
        Return the key used to group the same security finding.

        Findings with the same name, risk and CWE are treated as
        the same vulnerability type while affected URLs are retained.
        """
        return (
            self.name,
            self.risk,
            self.cwe_id,
        )