"""Prompt-injection screening for untrusted evidence text.

Evidence is data, never instructions. This screen flags text that tries to address
an AI system; flagged chunks are excluded from any LLM context and surfaced to the
reviewer. Detection is a signal, not the defense: the real controls are (1) the AI
cannot write results or scores, (2) LLM context is delimited data, (3) structured
output validation, (4) human approval."""
from __future__ import annotations

import re

PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts?)",
    r"disregard (all |the )?(previous|prior|above|system)",
    r"you are now (a|an|the)\b",
    r"\bsystem prompt\b",
    r"\b(assistant|system)\s*:\s",
    r"(mark|set|record|score) (all|every|each|this|these)?\s*(controls?|requirements?|objectives?|practices?).{0,30}\b(met|compliant|passed)\b",
    r"\bnew instructions\b",
    r"do not (tell|inform|alert) (the )?(user|assessor|reviewer)",
    r"<\s*/?\s*(system|instructions?)\s*>",
    r"\bjailbreak\b",
]
_RX = [re.compile(p, re.I) for p in PATTERNS]


def screen(text: str) -> list[str]:
    return [p.pattern for p in _RX if p.search(text)]
