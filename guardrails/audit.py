from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class AuditRecord:
    timestamp_utc: str
    user_input: str
    processed_input: str
    final_output: str
    final_decision: str
    risk_score: Dict[str, Any]
    triggered_policies: List[str] = field(default_factory=list)
    trace: List[Dict[str, Any]] = field(default_factory=list)
    tool_used: str | None = None
    tool_args: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)