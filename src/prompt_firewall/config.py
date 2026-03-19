"""
Configuration and rule management for prompt-firewall.
"""
from __future__ import annotations

import json
import os
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


RULES_DIR = Path(__file__).parent / "rules"


class SensitivityLevel(str, Enum):
    PERMISSIVE = "permissive"
    MODERATE = "moderate"
    STRICT = "strict"


# Threshold map: sensitivity → minimum ThreatLevel that causes a block
SENSITIVITY_THRESHOLDS = {
    SensitivityLevel.PERMISSIVE: "high",
    SensitivityLevel.MODERATE: "medium",
    SensitivityLevel.STRICT: "low",
}


class DetectorConfig(BaseModel):
    enabled: bool = True
    extra_patterns: List[str] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)


class FirewallConfig(BaseModel):
    sensitivity: SensitivityLevel = SensitivityLevel.MODERATE
    block_on_threshold: bool = True
    detectors: Dict[str, DetectorConfig] = Field(default_factory=dict)
    custom_injection_patterns: List[str] = Field(default_factory=list)
    custom_jailbreak_patterns: List[str] = Field(default_factory=list)
    canary_tokens: List[str] = Field(default_factory=list)
    max_input_length: int = 32_000       # characters
    max_token_count: int = 8_000         # tokens (approx)
    enable_pii_detection: bool = True
    enable_output_scanning: bool = True
    log_blocked: bool = True

    def get_detector_config(self, name: str) -> DetectorConfig:
        return self.detectors.get(name, DetectorConfig())

    def is_detector_enabled(self, name: str) -> bool:
        return self.get_detector_config(name).enabled

    @property
    def block_threshold(self) -> str:
        return SENSITIVITY_THRESHOLDS[self.sensitivity]

    @classmethod
    def strict(cls) -> "FirewallConfig":
        return cls(sensitivity=SensitivityLevel.STRICT)

    @classmethod
    def moderate(cls) -> "FirewallConfig":
        return cls(sensitivity=SensitivityLevel.MODERATE)

    @classmethod
    def permissive(cls) -> "FirewallConfig":
        return cls(sensitivity=SensitivityLevel.PERMISSIVE)

    @classmethod
    def from_file(cls, path: str | Path) -> "FirewallConfig":
        with open(path) as f:
            data = json.load(f)
        return cls(**data)


def load_json_rules(filename: str) -> List[Dict]:
    """Load rule definitions from the bundled rules directory."""
    path = RULES_DIR / filename
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)
