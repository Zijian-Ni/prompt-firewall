"""
Encoding obfuscation detector.
Detects base64, hex, rot13, unicode homoglyph attacks, and invisible characters.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

from prompt_firewall.config import FirewallConfig
from prompt_firewall.detectors.base import BaseDetector
from prompt_firewall.models import DetectorResult, ThreatLevel

# Invisible / zero-width characters
_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]"
)

# Hex blobs: sequences like 0x41 0x42 or \x41\x42 or 4142434445
_HEX_SEQUENCE = re.compile(r"((?:0x[0-9a-fA-F]{2}[\s,]?){6,}|(?:\\x[0-9a-fA-F]{2}){6,}|(?:[0-9a-fA-F]{2}\s){10,})")

# Base64 blobs of at least 40 chars (roughly 30+ raw bytes)
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Homoglyph: Cyrillic/Greek lookalikes mixed into ASCII words
_CYRILLIC = re.compile(r"[а-яёА-ЯЁ]")
_GREEK = re.compile(r"[α-ωΑ-Ω]")

# Suspicious injection keywords (checked after decoding)
_INJECTION_KEYWORDS = re.compile(
    r"(?i)(ignore\s+(previous|all)\s+instructions?|you\s+are\s+now|do\s+anything\s+now"
    r"|system\s+prompt|jailbreak|DAN\s+mode|developer\s+mode)"
)


def _try_decode_base64(text: str) -> str | None:
    """Return decoded UTF-8 if text looks like base64, else None."""
    try:
        decoded_bytes = base64.b64decode(text + "==", validate=False)
        decoded = decoded_bytes.decode("utf-8", errors="ignore")
        if len(decoded.strip()) > 5 and decoded.isprintable() or "\n" in decoded:
            return decoded
    except Exception:
        pass
    return None


def _try_decode_hex(text: str) -> str | None:
    """Return decoded text from hex sequence."""
    hex_cleaned = re.sub(r"(0x|\\x|\s|,)", "", text)
    try:
        decoded_bytes = bytes.fromhex(hex_cleaned)
        decoded = decoded_bytes.decode("utf-8", errors="ignore")
        if len(decoded.strip()) > 5:
            return decoded
    except Exception:
        pass
    return None


def _try_rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


class EncodingDetector(BaseDetector):
    """Detects obfuscated payloads via encoding analysis."""

    name = "encoding"

    def scan(self, text: str) -> DetectorResult:
        matches = []
        highest = ThreatLevel.SAFE

        # 1. Invisible characters
        inv = _INVISIBLE_CHARS.findall(text)
        if inv:
            matches.append(f"invisible_chars: {len(inv)} zero-width/invisible Unicode characters found")
            highest = ThreatLevel.HIGH

        # 2. Base64 blobs
        for blob in _BASE64_BLOB.findall(text):
            decoded = _try_decode_base64(blob)
            if decoded and _INJECTION_KEYWORDS.search(decoded):
                matches.append(f"base64_injection: decoded content contains injection keywords: {decoded[:80]!r}")
                highest = ThreatLevel.CRITICAL
            elif decoded and len(decoded) > 20:
                matches.append(f"base64_payload: possibly encoded payload (decoded: {decoded[:60]!r})")
                if highest < ThreatLevel.MEDIUM:
                    highest = ThreatLevel.MEDIUM

        # 3. Hex sequences
        for hex_blob in _HEX_SEQUENCE.findall(text):
            decoded = _try_decode_hex(hex_blob)
            if decoded and _INJECTION_KEYWORDS.search(decoded):
                matches.append(f"hex_injection: decoded hex contains injection keywords: {decoded[:80]!r}")
                highest = ThreatLevel.CRITICAL
            elif decoded:
                matches.append(f"hex_payload: hex-encoded payload found (decoded: {decoded[:60]!r})")
                if highest < ThreatLevel.MEDIUM:
                    highest = ThreatLevel.MEDIUM

        # 4. ROT13
        rot = _try_rot13(text)
        if _INJECTION_KEYWORDS.search(rot):
            matches.append(f"rot13_injection: ROT13-decoded content contains injection keywords")
            if highest < ThreatLevel.HIGH:
                highest = ThreatLevel.HIGH

        # 5. Homoglyph attacks (Cyrillic/Greek mixed with Latin)
        ascii_words = re.findall(r'\b[A-Za-z]{3,}\b', text)
        all_alpha = re.findall(r'\b[\w]{3,}\b', text)
        if _CYRILLIC.search(text) or _GREEK.search(text):
            # Check if mixed in the same "word" context
            for char in text:
                cat = unicodedata.category(char)
                name = unicodedata.name(char, "")
                if ("CYRILLIC" in name or "GREEK" in name) and char.isalpha():
                    matches.append(f"homoglyph_attack: non-Latin lookalike character detected: U+{ord(char):04X} ({name})")
                    if highest < ThreatLevel.HIGH:
                        highest = ThreatLevel.HIGH
                    break

        triggered = bool(matches)
        confidence = min(1.0, len(matches) * 0.4) if triggered else 0.0

        return DetectorResult(
            detector=self.name,
            triggered=triggered,
            threat_level=highest,
            matches=matches,
            explanation="; ".join(matches[:3]),
            confidence=confidence,
        )
