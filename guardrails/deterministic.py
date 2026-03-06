from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class DeterministicPolicy:
    banned_keywords: List[str]

    def check(self, text: str) -> Tuple[bool, List[str]]:
        t = (text or "").lower()
        hits = [kw for kw in self.banned_keywords if kw.lower() in t]
        return len(hits) > 0, hits