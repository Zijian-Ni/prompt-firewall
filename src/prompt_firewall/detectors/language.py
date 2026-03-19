"""
Language consistency detector.
Detects mid-prompt language switching — a common prompt injection technique
where attackers inject instructions in a different language to bypass filters.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from prompt_firewall.config import FirewallConfig
from prompt_firewall.detectors.base import BaseDetector
from prompt_firewall.models import DetectorResult, ThreatLevel

# Unicode script block detection (simplified heuristics)
_SCRIPT_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("Latin", re.compile(r"[A-Za-z]{4,}")),
    ("CJK", re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf\u20000-\u2a6df]")),
    ("Arabic", re.compile(r"[\u0600-\u06ff\u0750-\u077f]")),
    ("Cyrillic", re.compile(r"[\u0400-\u04ff]")),
    ("Hebrew", re.compile(r"[\u0590-\u05ff]")),
    ("Devanagari", re.compile(r"[\u0900-\u097f]")),
    ("Thai", re.compile(r"[\u0e00-\u0e7f]")),
    ("Korean", re.compile(r"[\uac00-\ud7af\u1100-\u11ff]")),
    ("Japanese_kana", re.compile(r"[\u3040-\u309f\u30a0-\u30ff]")),
]

# Injection keyword list in multiple languages
_MULTILANG_INJECTION = re.compile(
    r"(?i)"
    r"(ignorez|ignorieren|ignora|忽略|无视|무시|ignorer)\s+(les\s+)?(précédentes?|vorherigen|anteriori|之前的|先前的|이전의?)?\s*(instructions?|Anweisungen|instrucciones|指令|지시)"
    r"|(?:oubliez|vergessen\s+Sie|olvida|忘记|忘れて|잊어버려)\s+(les\s+)?(instructions?|alles|todo|所有的?)",
    re.DOTALL,
)


def _dominant_script(text: str) -> str | None:
    scores: dict[str, int] = {}
    for name, pattern in _SCRIPT_PATTERNS:
        found = pattern.findall(text)
        if found:
            scores[name] = sum(len(f) for f in found)
    if not scores:
        return None
    return max(scores, key=lambda k: scores[k])


def _detect_script_switching(text: str, min_block: int = 10) -> List[str]:
    """Split text into sentences and check if scripts switch unexpectedly."""
    sentences = re.split(r"[.!?\n]{1,3}", text)
    if len(sentences) < 3:
        return []

    scripts = []
    for sent in sentences:
        if len(sent.strip()) < min_block:
            continue
        dom = _dominant_script(sent)
        if dom:
            scripts.append(dom)

    if len(set(scripts)) <= 1:
        return []

    switches = []
    for i in range(1, len(scripts)):
        if scripts[i] != scripts[i - 1]:
            switches.append(f"{scripts[i-1]} → {scripts[i]}")

    return switches


class LanguageDetector(BaseDetector):
    """Detects language switching and multi-language injection patterns."""

    name = "language"

    def scan(self, text: str) -> DetectorResult:
        matches = []
        highest = ThreatLevel.SAFE

        # 1. Check for multi-language injection keywords
        m = _MULTILANG_INJECTION.search(text)
        if m:
            matches.append(f"multilang_injection: injection keyword in non-English language: {m.group(0)[:80]!r}")
            highest = ThreatLevel.HIGH

        # 2. Detect script switching across sentences
        switches = _detect_script_switching(text)
        if len(switches) >= 2:
            matches.append(f"script_switching: {len(switches)} script changes detected ({', '.join(switches[:3])})")
            if highest < ThreatLevel.MEDIUM:
                highest = ThreatLevel.MEDIUM
        elif switches:
            matches.append(f"script_switch: script change detected ({switches[0]})")
            if highest < ThreatLevel.LOW:
                highest = ThreatLevel.LOW

        triggered = bool(matches)
        confidence = min(1.0, len(matches) * 0.45) if triggered else 0.0

        return DetectorResult(
            detector=self.name,
            triggered=triggered,
            threat_level=highest,
            matches=matches,
            explanation="; ".join(matches),
            confidence=confidence,
        )
