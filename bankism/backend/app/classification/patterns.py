"""Threat signature patterns for prompt injection, jailbreaks, and payment exploit metadata."""

import re
from typing import List, Tuple
from ..schemas.common import ThreatCategory, RiskLevel

# Structure: (Pattern, ThreatCategory, Confidence, Severity, Description)
PROMPT_INJECTION_PATTERNS: List[Tuple[re.Pattern, ThreatCategory, float, RiskLevel, str]] = [
    (
        re.compile(r"(?i)\b(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|commands|constraints)\b"),
        ThreatCategory.PROMPT_INJECTION,
        0.95,
        RiskLevel.CRITICAL,
        "Instruction override attempting to disregard prior system constraints",
    ),
    (
        re.compile(r"(?i)\b(new\s+system\s+prompt|system\s+override|admin\s+mode\s+enabled|root\s+access\s+granted)\b"),
        ThreatCategory.PROMPT_INJECTION,
        0.92,
        RiskLevel.CRITICAL,
        "System prompt boundary spoofing attempt",
    ),
    (
        re.compile(r"(?i)\b(you\s+are\s+now|from\s+now\s+on\s+you\s+must|starting\s+now\s+act\s+as)\s+(an?\s+)?(unrestricted|evil|dan|jailbroken|godmode|developer)\b"),
        ThreatCategory.PROMPT_INJECTION,
        0.90,
        RiskLevel.CRITICAL,
        "Persona hijacking attempting to enforce unrestricted persona",
    ),
    (
        re.compile(r"(?i)(<!--.*?-->|\[system\]|\[assistant\]|<im_start>|<\|im_end\|>|\[INST\]|\[\/INST\])"),
        ThreatCategory.PROMPT_INJECTION,
        0.88,
        RiskLevel.HIGH,
        "Adversarial chat template marker injection",
    ),
    (
        re.compile(r"(?i)\b(repeat\s+after\s+me|print\s+the\s+(entire\s+)?system\s+prompt|reveal\s+(your\s+)?hidden\s+instructions)\b"),
        ThreatCategory.PROMPT_INJECTION,
        0.85,
        RiskLevel.HIGH,
        "System prompt exfiltration probe",
    ),
]

JAILBREAK_PATTERNS: List[Tuple[re.Pattern, ThreatCategory, float, RiskLevel, str]] = [
    (
        re.compile(r"(?i)\b(dan|do\s+anything\s+now|bypass\s+all\s+safety|jailbreak|chaos\s+mode|unfiltered\s+mode)\b"),
        ThreatCategory.JAILBREAK_ATTEMPT,
        0.95,
        RiskLevel.CRITICAL,
        "Direct jailbreak keyword invocation",
    ),
    (
        re.compile(r"(?i)\b(in\s+a\s+fictional\s+world|hypothetical\s+roleplay|for\s+educational\s+purposes\s+only|pretend\s+there\s+are\s+no\s+regulations)\b.*\b(steal|wire|transfer|hack|empty\s+account|drain)\b"),
        ThreatCategory.JAILBREAK_ATTEMPT,
        0.90,
        RiskLevel.CRITICAL,
        "Hypothetical/roleplay framing designed to bypass banking rules",
    ),
    (
        re.compile(r"(?i)\b(act\s+as\s+my\s+deceased\s+grandmother|grandma\s+story|hypothetical\s+scenario)\b.*\b(password|credentials|secret|transfer)\b"),
        ThreatCategory.JAILBREAK_ATTEMPT,
        0.85,
        RiskLevel.HIGH,
        "Emotional manipulation / social engineering jailbreak frame",
    ),
    (
        re.compile(r"(?i)\b(developer\s+mode\s+output|diagnostic\s+mode\s*:\s*execute|bypass_auth\s*=\s*true)\b"),
        ThreatCategory.JAILBREAK_ATTEMPT,
        0.90,
        RiskLevel.CRITICAL,
        "Pseudo-technical bypass mode invocation",
    ),
]

MALICIOUS_PAYMENT_METADATA_PATTERNS: List[Tuple[re.Pattern, ThreatCategory, float, RiskLevel, str]] = [
    # SQL Injection in payment memo / destination
    (
        re.compile(r"(?i)('|\b)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set|or\s+1\s*=\s*1|--|#|/\*|\*/)\b"),
        ThreatCategory.MALICIOUS_PAYMENT_METADATA,
        0.95,
        RiskLevel.CRITICAL,
        "SQL injection syntax detected in payment field",
    ),
    # Cross Site Scripting (XSS)
    (
        re.compile(r"(?i)(<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\(|<img\s+src=)"),
        ThreatCategory.MALICIOUS_PAYMENT_METADATA,
        0.92,
        RiskLevel.HIGH,
        "Cross-site scripting (XSS) payload in payment metadata",
    ),
    # Command Injection
    (
        re.compile(r"(;|&&|\|\|)\s*(rm\s+-rf|cat\s+/etc/passwd|curl\s+|wget\s+|nc\s+|bash\s+-i|sh\s+-i|powershell)"),
        ThreatCategory.MALICIOUS_PAYMENT_METADATA,
        0.98,
        RiskLevel.CRITICAL,
        "Shell command execution sequence injected in payment metadata",
    ),
    # SSRF / Suspicious protocol URLs in payment memo
    (
        re.compile(r"(?i)\b(gopher|ldap|file|dict|ftp)://[^\s]+"),
        ThreatCategory.MALICIOUS_PAYMENT_METADATA,
        0.88,
        RiskLevel.HIGH,
        "Dangerous URI protocol scheme detected in transaction data",
    ),
]

AMBIGUOUS_INTENT_PATTERNS: List[Tuple[re.Pattern, ThreatCategory, float, RiskLevel, str]] = [
    (
        re.compile(r"(?i)\b(send\s+(all|everything|whatever|some)\s+(my\s+)?(money|cash|balance|funds)\s+to\s+(someone|whoever|anyone|them|that\s+guy))\b"),
        ThreatCategory.AMBIGUOUS_INTENT,
        0.85,
        RiskLevel.HIGH,
        "Vague recipient and unbounded transaction amount requested",
    ),
    (
        re.compile(r"(?i)\b(transfer\s+(a\s+bunch\s+of|a\s+lot\s+of|some)\s+(cash|money|dollars))\b"),
        ThreatCategory.AMBIGUOUS_INTENT,
        0.75,
        RiskLevel.MEDIUM,
        "Ambiguous transaction quantity requires explicit user clarification",
    ),
    (
        re.compile(r"(?i)\b(do\s+whatever\s+is\s+necessary\s+with\s+my\s+account)\b"),
        ThreatCategory.AMBIGUOUS_INTENT,
        0.80,
        RiskLevel.HIGH,
        "Blanket unstructured delegation without specific operational parameters",
    ),
]
