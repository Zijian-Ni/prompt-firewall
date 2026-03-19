"""
Data models for prompt-firewall.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    """Severity level of detected threats."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: "ThreatLevel") -> bool:
        order = [ThreatLevel.SAFE, ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "ThreatLevel") -> bool:
        return self == other or self < other

    def __gt__(self, other: "ThreatLevel") -> bool:
        return not self <= other

    def __ge__(self, other: "ThreatLevel") -> bool:
        return not self < other


class DetectorResult(BaseModel):
    """Result from a single detector."""
    detector: str = Field(..., description="Name of the detector")
    triggered: bool = Field(False, description="Whether the detector was triggered")
    threat_level: ThreatLevel = Field(ThreatLevel.SAFE, description="Detected threat level")
    matches: List[str] = Field(default_factory=list, description="Matched patterns or tokens")
    explanation: str = Field("", description="Human-readable explanation")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence score [0, 1]")


class ScanResult(BaseModel):
    """Aggregated result of scanning a prompt through all detectors."""
    text: str = Field(..., description="The scanned text (truncated for display)")
    blocked: bool = Field(False, description="Whether the prompt should be blocked")
    threat_level: ThreatLevel = Field(ThreatLevel.SAFE, description="Highest threat level found")
    detectors: List[DetectorResult] = Field(default_factory=list, description="Individual detector results")
    explanation: str = Field("", description="Summary explanation")
    triggered_detectors: List[str] = Field(default_factory=list, description="Names of triggered detectors")

    @property
    def is_safe(self) -> bool:
        return not self.blocked

    def summary(self) -> str:
        if not self.blocked:
            return f"✅ SAFE — No threats detected"
        triggered = ", ".join(self.triggered_detectors)
        return f"🚨 BLOCKED [{self.threat_level.upper()}] — Triggered: {triggered}\n{self.explanation}"
