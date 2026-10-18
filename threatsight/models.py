from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AttackMapping:
    framework: str
    technique_id: Optional[str]
    technique_name: Optional[str]
    mapped: bool


@dataclass(frozen=True)
class Finding:
    event_id: str
    threat_category: str
    severity: Severity
    confidence: float
    matched_indicators: list[str]
    evidence: list[str]
    attack_mapping: AttackMapping
    mapping_rationale: str
    recommended_action: str

    def to_dict(self) -> dict:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result
