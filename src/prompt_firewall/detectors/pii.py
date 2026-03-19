"""
PII (Personally Identifiable Information) detector.
Detects emails, phone numbers, SSNs, credit cards, and IP addresses.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from prompt_firewall.config import FirewallConfig
from prompt_firewall.detectors.base import BaseDetector
from prompt_firewall.models import DetectorResult, ThreatLevel

_PII_PATTERNS: List[Tuple[str, re.Pattern, ThreatLevel]] = [
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        ThreatLevel.MEDIUM,
    ),
    (
        "ssn",
        re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
        ThreatLevel.HIGH,
    ),
    (
        "credit_card",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
            r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}"
            r"|(?:2131|1800|35\d{3})\d{11})\b"
        ),
        ThreatLevel.CRITICAL,
    ),
    (
        "phone_us",
        re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        ThreatLevel.MEDIUM,
    ),
    (
        "phone_intl",
        re.compile(r"\+(?:[1-9]\d{0,2})[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b"),
        ThreatLevel.LOW,
    ),
    (
        "ipv4",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        ThreatLevel.LOW,
    ),
    (
        "ipv6",
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
            r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
            r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
        ),
        ThreatLevel.LOW,
    ),
    (
        "uk_nino",
        re.compile(r"\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[\s]?\d{2}[\s]?\d{2}[\s]?\d{2}[\s]?[A-D]\b", re.I),
        ThreatLevel.HIGH,
    ),
    (
        "passport_number",
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        ThreatLevel.MEDIUM,
    ),
    (
        "api_key_generic",
        re.compile(r"\b(sk-[A-Za-z0-9]{20,}|pk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_\-]{35})\b"),
        ThreatLevel.CRITICAL,
    ),
    (
        "aws_key",
        re.compile(r"\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b"),
        ThreatLevel.CRITICAL,
    ),
]


def _redact(text: str, match: re.Match) -> str:
    start, end = match.span()
    return f"{text[:start]}[REDACTED]{text[end:]}"


class PIIDetector(BaseDetector):
    """Detects PII in both input prompts and LLM output responses."""

    name = "pii"

    def scan(self, text: str) -> DetectorResult:
        matches = []
        highest = ThreatLevel.SAFE

        for label, pattern, level in _PII_PATTERNS:
            found = pattern.findall(text)
            if found:
                # Don't log the actual PII values — just counts and type
                matches.append(f"{label}: {len(found)} instance(s) detected")
                if level > highest:
                    highest = level

        triggered = bool(matches)
        confidence = min(1.0, len(matches) * 0.5) if triggered else 0.0

        return DetectorResult(
            detector=self.name,
            triggered=triggered,
            threat_level=highest,
            matches=matches,
            explanation="; ".join(matches),
            confidence=confidence,
        )

    def redact(self, text: str) -> str:
        """Return a copy of text with all PII replaced by [REDACTED]."""
        for _, pattern, _ in _PII_PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text
