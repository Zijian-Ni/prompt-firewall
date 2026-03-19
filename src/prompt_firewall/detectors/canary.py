"""
Canary token detector.
Detects if the model output contains planted canary tokens,
indicating a system-prompt extraction attack succeeded.
"""
from __future__ import annotations

import re
from typing import List

from prompt_firewall.config import FirewallConfig
from prompt_firewall.detectors.base import BaseDetector
from prompt_firewall.models import DetectorResult, ThreatLevel


class CanaryDetector(BaseDetector):
    """
    Detect canary tokens in model output.

    Usage:
        1. Plant a secret canary token in your system prompt:
               config.canary_tokens = ["CANARY-7f3a2b9e"]
        2. Scan the model's *output* with this detector.
        3. If the output contains the canary, the system prompt was leaked.
    """

    name = "canary"

    def __init__(self, config: FirewallConfig) -> None:
        super().__init__(config)
        self._tokens: List[re.Pattern] = []
        for token in config.canary_tokens:
            try:
                self._tokens.append(re.compile(re.escape(token)))
            except re.error:
                pass

    def scan(self, text: str) -> DetectorResult:
        if not self._tokens:
            return DetectorResult(
                detector=self.name,
                triggered=False,
                threat_level=ThreatLevel.SAFE,
                explanation="No canary tokens configured",
            )

        matches = []
        for pattern in self._tokens:
            if pattern.search(text):
                matches.append(f"canary_token_leak: '{pattern.pattern}' found in output")

        triggered = bool(matches)
        level = ThreatLevel.CRITICAL if triggered else ThreatLevel.SAFE
        explanation = (
            "SYSTEM PROMPT LEAKED: canary token(s) found in model output, "
            "indicating successful system-prompt extraction attack."
            if triggered
            else ""
        )

        return DetectorResult(
            detector=self.name,
            triggered=triggered,
            threat_level=level,
            matches=matches,
            explanation=explanation,
            confidence=1.0 if triggered else 0.0,
        )
