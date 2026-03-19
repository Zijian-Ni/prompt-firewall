"""
Abstract base class for all prompt-firewall detectors.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from prompt_firewall.config import FirewallConfig
    from prompt_firewall.models import DetectorResult


class BaseDetector(ABC):
    """All detectors must inherit from this class."""

    #: Override in subclasses with a unique, stable identifier.
    name: str = "base"

    def __init__(self, config: "FirewallConfig") -> None:
        self.config = config
        self.detector_config = config.get_detector_config(self.name)

    @abstractmethod
    def scan(self, text: str) -> "DetectorResult":
        """
        Scan the given text and return a DetectorResult.

        Args:
            text: The prompt or response text to analyse.

        Returns:
            A DetectorResult describing what (if anything) was found.
        """
        ...

    @property
    def enabled(self) -> bool:
        return self.detector_config.enabled
