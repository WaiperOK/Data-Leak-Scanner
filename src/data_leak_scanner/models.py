from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(slots=True)
class LeakFinding:
    detector_id: str
    severity: Severity
    label: str
    match: str
    start: int
    end: int

    def to_dict(self) -> dict[str, object]:
        return {
            "detector_id": self.detector_id,
            "severity": self.severity.value,
            "label": self.label,
            "match": self.match,
            "start": self.start,
            "end": self.end,
        }
