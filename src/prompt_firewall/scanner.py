"""
Scanner: orchestrates all detectors and aggregates results.
"""
from __future__ import annotations

import logging
from typing import List, Type

from prompt_firewall.config import FirewallConfig
from prompt_firewall.detectors.base import BaseDetector
from prompt_firewall.detectors.injection import InjectionDetector
from prompt_firewall.detectors.jailbreak import JailbreakDetector
from prompt_firewall.detectors.encoding import EncodingDetector
from prompt_firewall.detectors.pii import PIIDetector
from prompt_firewall.detectors.canary import CanaryDetector
from prompt_firewall.detectors.length import LengthDetector
from prompt_firewall.detectors.language import LanguageDetector
from prompt_firewall.models import DetectorResult, ScanResult, ThreatLevel

log = logging.getLogger(__name__)

_ALL_DETECTOR_CLASSES: List[Type[BaseDetector]] = [
    InjectionDetector,
    JailbreakDetector,
    EncodingDetector,
    PIIDetector,
    CanaryDetector,
    LengthDetector,
    LanguageDetector,
]

_THRESHOLD_ORDER = [
    ThreatLevel.SAFE,
    ThreatLevel.LOW,
    ThreatLevel.MEDIUM,
    ThreatLevel.HIGH,
    ThreatLevel.CRITICAL,
]
_THRESHOLD_INDEX = {v: i for i, v in enumerate(_THRESHOLD_ORDER)}


def _should_block(threat_level: ThreatLevel, threshold: str) -> bool:
    threshold_level = ThreatLevel(threshold)
    return _THRESHOLD_INDEX[threat_level] >= _THRESHOLD_INDEX[threshold_level]


class Scanner:
    """Runs all enabled detectors and produces a ScanResult."""

    def __init__(self, config: FirewallConfig) -> None:
        self.config = config
        self._detectors: List[BaseDetector] = []
        for cls in _ALL_DETECTOR_CLASSES:
            detector = cls(config)
            if detector.enabled:
                self._detectors.append(detector)
            else:
                log.debug("Detector '%s' is disabled", cls.name)

    def add_detector(self, detector: BaseDetector) -> None:
        """Register a custom detector."""
        self._detectors.append(detector)

    def scan(self, text: str) -> ScanResult:
        if not text or not text.strip():
            return ScanResult(
                text=text,
                blocked=False,
                threat_level=ThreatLevel.SAFE,
                explanation="Empty input",
            )

        results: List[DetectorResult] = []
        highest_level = ThreatLevel.SAFE
        triggered_names: List[str] = []
        explanations: List[str] = []

        for detector in self._detectors:
            try:
                result = detector.scan(text)
                results.append(result)
                if result.triggered:
                    triggered_names.append(detector.name)
                    if _THRESHOLD_INDEX[result.threat_level] > _THRESHOLD_INDEX[highest_level]:
                        highest_level = result.threat_level
                    if result.explanation:
                        explanations.append(f"[{detector.name}] {result.explanation}")
            except Exception as exc:
                log.warning("Detector '%s' raised an exception: %s", detector.name, exc)

        should_block = (
            self.config.block_on_threshold
            and _should_block(highest_level, self.config.block_threshold)
        )

        if should_block and self.config.log_blocked:
            log.warning(
                "Blocked prompt [%s] — detectors: %s — %.80r",
                highest_level,
                triggered_names,
                text,
            )

        return ScanResult(
            text=text[:500],  # never store full text in result
            blocked=should_block,
            threat_level=highest_level,
            detectors=results,
            explanation="\n".join(explanations),
            triggered_detectors=triggered_names,
        )
