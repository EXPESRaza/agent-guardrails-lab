from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class PromptInjectionPolicy:
    patterns: List[str]

    def check(self, text: str) -> Tuple[bool, List[str]]:
        t = (text or "").lower()
        hits = [p for p in self.patterns if p.lower() in t]
        return len(hits) > 0, hits