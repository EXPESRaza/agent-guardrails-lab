from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RiskScore:
    total: int = 0
    reasons: List[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.total += points
        self.reasons.append(f"+{points}: {reason}")

    def to_dict(self) -> Dict:
        return {
            "total": self.total,
            "reasons": self.reasons,
        }