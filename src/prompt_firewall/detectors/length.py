"""
Length and repetition detector.
Flags abnormally long inputs and token-stuffing / repetition attacks.
"""
from __future__ import annotations

import re

from prompt_firewall.config import FirewallConfig
from prompt_firewall.detectors.base import BaseDetector
from prompt_firewall.models import DetectorResult, ThreatLevel

# Repetition: same token repeated many times
_REPEATED_WORD = re.compile(r"\b(\w{3,})\b(?:\s+\1){9,}", re.IGNORECASE)

# Repeated punctuation blocks (attention sink attacks)
_REPEATED_PUNCT = re.compile(r"([!?.,:;|]{3,})")

# Null-byte / control character stuffing
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _count_repetition_score(text: str) -> float:
    """Heuristic: what fraction of characters are in repeated blocks."""
    words = text.lower().split()
    if len(words) < 10:
        return 0.0
    from collections import Counter
    counts = Counter(words)
    repeated_chars = sum(len(w) * (c - 1) for w, c in counts.items() if c > 3)
    return repeated_chars / max(len(text), 1)


class LengthDetector(BaseDetector):
    """Detects token-stuffing, repetition, and abnormal length."""

    name = "length"

    def scan(self, text: str) -> DetectorResult:
        matches = []
        highest = ThreatLevel.SAFE
        char_count = len(text)
        options = self.detector_config.options

        max_chars = options.get("max_chars", self.config.max_input_length)
        warn_chars = options.get("warn_chars", max_chars // 2)

        # 1. Hard length limit
        if char_count > max_chars:
            matches.append(f"input_too_long: {char_count} chars exceeds limit {max_chars}")
            highest = ThreatLevel.HIGH

        elif char_count > warn_chars:
            matches.append(f"input_long: {char_count} chars (warn threshold: {warn_chars})")
            if highest < ThreatLevel.LOW:
                highest = ThreatLevel.LOW

        # 2. Repeated word patterns
        for m in _REPEATED_WORD.finditer(text):
            matches.append(f"word_repetition: '{m.group(1)}' repeated many times")
            if highest < ThreatLevel.MEDIUM:
                highest = ThreatLevel.MEDIUM

        # 3. Repetition score
        rep_score = _count_repetition_score(text)
        if rep_score > 0.6:
            matches.append(f"high_repetition_ratio: {rep_score:.0%} of content is repetitive (possible token stuffing)")
            if highest < ThreatLevel.HIGH:
                highest = ThreatLevel.HIGH
        elif rep_score > 0.3:
            matches.append(f"moderate_repetition: {rep_score:.0%} repetition ratio")
            if highest < ThreatLevel.MEDIUM:
                highest = ThreatLevel.MEDIUM

        # 4. Control characters
        ctrl = _CONTROL_CHARS.findall(text)
        if ctrl:
            matches.append(f"control_chars: {len(ctrl)} control/null byte(s) detected")
            if highest < ThreatLevel.HIGH:
                highest = ThreatLevel.HIGH

        triggered = bool(matches)
        confidence = min(1.0, len(matches) * 0.3) if triggered else 0.0

        return DetectorResult(
            detector=self.name,
            triggered=triggered,
            threat_level=highest,
            matches=matches,
            explanation="; ".join(matches[:3]),
            confidence=confidence,
        )
