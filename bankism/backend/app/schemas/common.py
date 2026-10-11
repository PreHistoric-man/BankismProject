"""Common enumerations and constants for Bankism."""

from enum import Enum


class Verdict(str, Enum):
    """Consistent security verdicts for banking firewall decisions."""

    APPROVE = "APPROVE"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class RiskLevel(str, Enum):
    """Normalized risk levels assigned to incoming banking requests."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    """Threat categories monitored by the Bankism firewall."""

    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK_ATTEMPT = "JAILBREAK_ATTEMPT"
    MALICIOUS_PAYMENT_METADATA = "MALICIOUS_PAYMENT_METADATA"
    OBFUSCATION = "OBFUSCATION"
    AMBIGUOUS_INTENT = "AMBIGUOUS_INTENT"
    INVALID_INPUT = "INVALID_INPUT"
    NO_DETECTED_THREAT = "NO_DETECTED_THREAT"
