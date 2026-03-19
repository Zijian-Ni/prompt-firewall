"""Tests for PIIDetector."""
import pytest
from prompt_firewall.config import FirewallConfig
from prompt_firewall.detectors.pii import PIIDetector
from prompt_firewall.models import ThreatLevel


@pytest.fixture
def detector():
    return PIIDetector(FirewallConfig())


class TestPIIDetector:
    def test_email_detected(self, detector):
        result = detector.scan("Contact me at test@example.com")
        assert result.triggered
        any_email = any("email" in m for m in result.matches)
        assert any_email

    def test_ssn_detected(self, detector):
        result = detector.scan("My SSN is 123-45-6789.")
        assert result.triggered
        assert result.threat_level >= ThreatLevel.HIGH

    def test_credit_card_detected(self, detector):
        result = detector.scan("Credit card: 4532015112830366")
        assert result.triggered
        assert result.threat_level == ThreatLevel.CRITICAL

    def test_us_phone_detected(self, detector):
        result = detector.scan("Call me at (555) 867-5309")
        assert result.triggered

    def test_aws_key_detected(self, detector):
        result = detector.scan("AWS key: AKIAIOSFODNN7EXAMPLE")
        assert result.triggered
        assert result.threat_level == ThreatLevel.CRITICAL

    def test_no_pii(self, detector):
        result = detector.scan("The weather is nice today.")
        assert not result.triggered

    def test_redact_email(self, detector):
        text = "Email me at test@example.com please."
        redacted = detector.redact(text)
        assert "test@example.com" not in redacted
        assert "[REDACTED]" in redacted

    def test_redact_ssn(self, detector):
        text = "SSN: 123-45-6789"
        redacted = detector.redact(text)
        assert "123-45-6789" not in redacted

    def test_ipv4_detected(self, detector):
        result = detector.scan("Server is at 192.168.1.100")
        assert result.triggered
