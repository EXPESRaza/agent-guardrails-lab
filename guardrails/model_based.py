from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class ModelBasedPolicy:
    openai_api_key: Optional[str] = None
    model: str = "gpt-4o-mini"

    def classify(self, text: str) -> Tuple[str, str]:
        if not text:
            return "safe", "Empty input."

        lowered = text.lower()
        unsafe_markers = [
            "hack", "exploit", "malware", "bomb", "steal", "phish",
            "bypass", "sql injection", "disable guardrails", "jailbreak"
        ]
        if any(x in lowered for x in unsafe_markers):
            return "unsafe", "Heuristic classifier flagged unsafe intent."

        if self.openai_api_key:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=self.openai_api_key)
                prompt = (
                    "Classify the following text as SAFE or UNSAFE for an AI agent. "
                    "Return one word only: SAFE or UNSAFE.\n\n"
                    f"Text:\n{text}"
                )
                resp = client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0,
                )
                out = (resp.choices[0].message.content or "").strip().upper()
                if "UNSAFE" in out:
                    return "unsafe", "LLM classifier flagged unsafe."
                return "safe", "LLM classifier flagged safe."
            except Exception as e:
                return "safe", f"Model unavailable, fallback safe. Error: {e}"

        return "safe", "No unsafe signal detected."