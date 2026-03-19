"""
Prompt injection detector.
Matches known injection patterns against the input text.
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

_MAX_MATCHES = 10  # cap matches reported


class InjectionDetector(BaseDetector):
    """Detects prompt injection attacks using regex pattern matching."""

    name = "injection"

    def __init__(self, config: FirewallConfig) -> None:
        super().__init__(config)
        rules = load_json_rules("injection_patterns.json")
        extra = self.detector_config.extra_patterns + config.custom_injection_patterns

        self._patterns: List[tuple[re.Pattern, ThreatLevel, str, str]] = []
        for rule in rules:
            try:
                pattern = re.compile(rule["pattern"])
                level = _LEVEL_MAP.get(rule.get("threat_level", "medium"), ThreatLevel.MEDIUM)
                self._patterns.append((pattern, level, rule["name"], rule.get("description", "")))
            except re.error:
                pass  # skip malformed patterns

        for extra_pat in extra:
            try:
                pattern = re.compile(extra_pat, re.IGNORECASE)
                self._patterns.append((pattern, ThreatLevel.HIGH, "custom", "Custom injection pattern"))
            except re.error:
                pass

    def scan(self, text: str) -> DetectorResult:
        matches = []
        highest_level = ThreatLevel.SAFE
        explanations = []

        for pattern, level, name, description in self._patterns:
            m = pattern.search(text)
            if m:
                matched_text = m.group(0)[:120]
                matches.append(f"[{name}] {matched_text!r}")
                if level > highest_level:
                    highest_level = level
                explanations.append(f"{name}: {description}")
                if len(matches) >= _MAX_MATCHES:
                    break

        triggered = len(matches) > 0
        explanation = "; ".join(explanations[:3])
        confidence = min(1.0, len(matches) * 0.25) if triggered else 0.0

        return DetectorResult(
            detector=self.name,
            triggered=triggered,
            threat_level=highest_level,
            matches=matches,
            explanation=explanation,
            confidence=confidence,
        )
