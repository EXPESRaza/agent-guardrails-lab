from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
APIKEY_RE = re.compile(r"\b[A-Za-z0-9_\-]{24,}\b")


@dataclass
class PIIRule:
    name: str
    strategy: str
    apply_to_input: bool = True
    apply_to_output: bool = True


def _mask(s: str, keep_last: int = 4) -> str:
    if len(s) <= keep_last:
        return "*" * len(s)
    return "*" * (len(s) - keep_last) + s[-keep_last:]


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


class PIIMiddleware:
    def __init__(self, rules: List[PIIRule]):
        self.rules = rules
        self.detectors: Dict[str, re.Pattern] = {
            "email": EMAIL_RE,
            "credit_card": CC_RE,
            "ip": IP_RE,
            "api_key": APIKEY_RE,
        }

    def _apply_strategy(self, value: str, strategy: str, pii_type: str) -> Tuple[str, bool]:
        if strategy == "redact":
            return f"[REDACTED_{pii_type.upper()}]", False
        if strategy == "mask":
            return _mask(value), False
        if strategy == "hash":
            return f"[HASH_{pii_type.upper()}:{_hash(value)}]", False
        if strategy == "block":
            return value, True
        return value, False

    def process(self, text: str, *, is_input: bool) -> Tuple[str, List[str], bool, List[str]]:
        if not text:
            return text, [], False, []

        notes: List[str] = []
        triggered: List[str] = []
        blocked = False
        out = text

        for rule in self.rules:
            if is_input and not rule.apply_to_input:
                continue
            if (not is_input) and not rule.apply_to_output:
                continue

            detector = self.detectors.get(rule.name)
            if not detector:
                continue

            matches = list(detector.finditer(out))
            if not matches:
                continue

            for m in reversed(matches):
                found = m.group(0)
                transformed, should_block = self._apply_strategy(found, rule.strategy, rule.name)
                triggered.append(f"pii:{rule.name}:{rule.strategy}")

                if should_block:
                    blocked = True
                    notes.append(f"Blocked due to {rule.name}.")
                else:
                    notes.append(f"Applied {rule.strategy} to {rule.name}.")
                    out = out[:m.start()] + transformed + out[m.end():]

        return out, notes, blocked, triggered