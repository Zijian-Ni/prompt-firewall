"""
Jailbreak detector.
Matches known jailbreak signatures (DAN, AIM, STAN, Developer Mode, etc.)
"""
from __future__ import annotations

import re
from typing import List

from prompt_firewall.config import FirewallConfig, load_json_rules
from prompt_firewall.detectors.base import BaseDetector
from prompt_firewall.models import DetectorResult, ThreatLevel

_LEVEL_MAP = {
    "low": ThreatLevel.LOW,
    "medium": ThreatLevel.MEDIUM,
    "high": ThreatLevel.HIGH,
    "critical": ThreatLevel.CRITICAL,
}


class JailbreakDetector(BaseDetector):
    """Detects known jailbreak techniques via regex signatures."""

    name = "jailbreak"

    def __init__(self, config: FirewallConfig) -> None:
        super().__init__(config)
        rules = load_json_rules("jailbreak_signatures.json")
        extra = self.detector_config.extra_patterns + config.custom_jailbreak_patterns

        self._patterns: List[tuple[re.Pattern, ThreatLevel, str, str]] = []
        for rule in rules:
            try:
                pattern = re.compile(rule["pattern"], re.DOTALL)
                level = _LEVEL_MAP.get(rule.get("threat_level", "high"), ThreatLevel.HIGH)
                self._patterns.append((pattern, level, rule["name"], rule.get("description", "")))
            except re.error:
                pass

        for pat in extra:
            try:
                self._patterns.append((re.compile(pat, re.IGNORECASE), ThreatLevel.HIGH, "custom", "Custom jailbreak pattern"))
            except re.error:
                pass

    def scan(self, text: str) -> DetectorResult:
        matches = []
        highest = ThreatLevel.SAFE
        explanations = []

        for pattern, level, name, description in self._patterns:
            m = pattern.search(text)
            if m:
                matched_text = m.group(0)[:120]
                matches.append(f"[{name}] {matched_text!r}")
                if level > highest:
                    highest = level
                explanations.append(f"{name}: {description}")

        triggered = bool(matches)
        confidence = min(1.0, len(matches) * 0.35) if triggered else 0.0

        return DetectorResult(
            detector=self.name,
            triggered=triggered,
            threat_level=highest,
            matches=matches,
            explanation="; ".join(explanations[:3]),
            confidence=confidence,
        )
