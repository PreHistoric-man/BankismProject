"""
Threat Classification & Adversarial Vector Detection Module
"""
import re
from typing import List, Tuple
from ..schemas.common import ThreatCategory, RiskLevel
from ..schemas.responses import ThreatDetail
from .sanitization import detect_zero_width_evasion


INJECTION_PATTERNS = re.compile(
    r"\b(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|commands)|(system\s+override|admin\s+mode\s+enabled)\b",
    re.IGNORECASE,
)

JAILBREAK_PATTERNS = re.compile(
    r"\b(dan|do\s+anything\s+now|bypass\s+all\s+safety|drain\s+account|chaos\s+mode|unfiltered\s+mode)\b",
    re.IGNORECASE,
)

SQLI_PATTERNS = re.compile(
    r"('|\b)(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|delete\s+from|or\s+1\s*=\s*1|--|#)",
    re.IGNORECASE,
)

CMD_PATTERNS = re.compile(
    r"(;|&&|\|\|)\s*(rm\s+-rf|cat\s+[^\s]+|curl\s+https?://|wget\s+https?://)",
    re.IGNORECASE,
)

XSS_PATTERNS = re.compile(
    r"(<script.*?>|javascript:|alert\(|onerror=)",
    re.IGNORECASE,
)

AMBIGUOUS_PATTERNS = re.compile(
    r"\b(send\s+(all|everything|whatever)\s+(my\s+)?(money|cash|balance)\s+to\s+(whoever|someone))\b",
    re.IGNORECASE,
)


def detect_threats(
    raw_prompt: str,
    sanitized_prompt: str,
    action: str = "",
    memo: str = ""
) -> Tuple[List[ThreatDetail], ThreatCategory, RiskLevel, float]:
    """
    Scans input for prompt injection, jailbreaks, malicious payment metadata, obfuscation,
    and returns detected threats, primary threat category, risk level, and composite score.
    """
    threats: List[ThreatDetail] = []

    # 1. Obfuscation detection
    if detect_zero_width_evasion(raw_prompt):
        threats.append(ThreatDetail(
            category=ThreatCategory.OBFUSCATION,
            confidence=0.88,
            description="Detected invisible zero-width character evasion sequence in untrusted prompt",
            matched_pattern="\\u200B zero-width byte sequence",
            severity=RiskLevel.HIGH
        ))

    # 2. Prompt Injection detection
    match_inj = INJECTION_PATTERNS.search(sanitized_prompt)
    if match_inj:
        threats.append(ThreatDetail(
            category=ThreatCategory.PROMPT_INJECTION,
            confidence=0.96,
            description="Instruction override attempting to disregard system constraints or switch modes",
            matched_pattern=match_inj.group(0),
            severity=RiskLevel.CRITICAL
        ))

    # 3. Jailbreak detection
    match_jb = JAILBREAK_PATTERNS.search(sanitized_prompt)
    if match_jb:
        threats.append(ThreatDetail(
            category=ThreatCategory.JAILBREAK_ATTEMPT,
            confidence=0.94,
            description="Persona hijacking or safety avoidance phrasing detected",
            matched_pattern=match_jb.group(0),
            severity=RiskLevel.CRITICAL
        ))

    # 4. Malicious Payment Metadata
    combined_meta = f"{memo} {sanitized_prompt} {action}"
    match_sqli = SQLI_PATTERNS.search(combined_meta)
    if match_sqli:
        threats.append(ThreatDetail(
            category=ThreatCategory.MALICIOUS_PAYMENT_METADATA,
            confidence=0.95,
            description="SQL injection syntax identified in payment memo or request parameters",
            matched_pattern=match_sqli.group(0),
            severity=RiskLevel.CRITICAL
        ))

    match_cmd = CMD_PATTERNS.search(combined_meta)
    if match_cmd:
        threats.append(ThreatDetail(
            category=ThreatCategory.MALICIOUS_PAYMENT_METADATA,
            confidence=0.98,
            description="Command injection chaining sequence identified in request parameters",
            matched_pattern=match_cmd.group(0),
            severity=RiskLevel.CRITICAL
        ))

    match_xss = XSS_PATTERNS.search(combined_meta)
    if match_xss:
        threats.append(ThreatDetail(
            category=ThreatCategory.MALICIOUS_PAYMENT_METADATA,
            confidence=0.92,
            description="Cross-site scripting (XSS) payload identified in memo field",
            matched_pattern=match_xss.group(0),
            severity=RiskLevel.HIGH
        ))

    # 5. Ambiguous intent
    match_amb = AMBIGUOUS_PATTERNS.search(sanitized_prompt)
    if match_amb:
        threats.append(ThreatDetail(
            category=ThreatCategory.AMBIGUOUS_INTENT,
            confidence=0.85,
            description="Ambiguous recipient and unbounded transfer amount requested",
            matched_pattern=match_amb.group(0),
            severity=RiskLevel.HIGH
        ))

    # Determine composite level & primary threat
    if not threats:
        return threats, ThreatCategory.NO_DETECTED_THREAT, RiskLevel.LOW, 0.05

    # Check highest severity
    severities = [t.severity for t in threats]
    if RiskLevel.CRITICAL in severities:
        overall_level = RiskLevel.CRITICAL
        risk_score = 0.95
    elif RiskLevel.HIGH in severities:
        overall_level = RiskLevel.HIGH
        risk_score = 0.78
    else:
        overall_level = RiskLevel.MEDIUM
        risk_score = 0.45

    primary_threat = threats[0].category
    return threats, primary_threat, overall_level, risk_score
