"""
Deterministic Policy Engine Module
"""
from typing import List, Tuple
from ..schemas.common import Verdict, RiskLevel, ThreatCategory
from ..schemas.responses import ThreatDetail, PolicyViolation
from ..config import settings


def evaluate_firewall_policies(
    threats: List[ThreatDetail],
    amount: float = 0.0,
    action: str = ""
) -> Tuple[Verdict, List[PolicyViolation], List[str], bool]:
    """
    Evaluates deterministic security rules (POL-001 through POL-007).
    Enforces strict fail-closed precedence: BLOCK > REVIEW > APPROVE.
    """
    violations: List[PolicyViolation] = []
    reasons: List[str] = []
    verdict = Verdict.APPROVE
    requires_step_up = False

    categories = {t.category for t in threats}

    # POL-001: System Instruction Override Guard
    if ThreatCategory.PROMPT_INJECTION in categories:
        verdict = Verdict.BLOCK
        violations.append(PolicyViolation(
            rule_id="POL-001",
            rule_name="Instruction Override Defense",
            description="Request attempts to override system prompt or alter operation boundaries.",
            required_action="Immediate deterministic BLOCK. Terminate evaluation."
        ))
        reasons.append("PROMPT_INJECTION detected: System override attempt")

    # POL-002: Safety Bypass & Jailbreak Defense
    if ThreatCategory.JAILBREAK_ATTEMPT in categories:
        verdict = Verdict.BLOCK
        violations.append(PolicyViolation(
            rule_id="POL-002",
            rule_name="Persona & Jailbreak Neutralizer",
            description="Persona hijack or safety filter circumvention framing detected.",
            required_action="Deterministic BLOCK. Prohibit downstream tool execution."
        ))
        reasons.append("JAILBREAK_ATTEMPT detected: Safety filter circumvention")

    # POL-003: Malicious Payment Metadata Guard
    if ThreatCategory.MALICIOUS_PAYMENT_METADATA in categories:
        verdict = Verdict.BLOCK
        violations.append(PolicyViolation(
            rule_id="POL-003",
            rule_name="Metadata Injection Filter",
            description="SQL injection, shell execution, or script injection in payment metadata.",
            required_action="Block transaction; discard unsanitized metadata parameters."
        ))
        reasons.append("MALICIOUS_PAYMENT_METADATA detected: Injection payload in parameters")

    # POL-004: Anti-Obfuscation Guard
    if ThreatCategory.OBFUSCATION in categories:
        verdict = Verdict.BLOCK
        violations.append(PolicyViolation(
            rule_id="POL-004",
            rule_name="Anti-Obfuscation Defense",
            description="Zero-width or invisible characters detected attempting to evade filter.",
            required_action="Block request; flag for adversarial evasion attempt."
        ))
        reasons.append("OBFUSCATION detected: Invisible zero-width byte sequence")

    # POL-005: High-Value Financial Transfer Step-Up Rule ($10,000 threshold)
    if amount >= settings.high_amount_threshold:
        requires_step_up = True
        if verdict != Verdict.BLOCK:
            verdict = Verdict.REVIEW
        violations.append(PolicyViolation(
            rule_id="POL-005",
            rule_name="High-Value Financial Transfer Gate",
            description=f"Transaction amount (${amount:,.2f}) meets or exceeds threshold (${settings.high_amount_threshold:,.2f}).",
            required_action="Mandate Step-Up MFA authentication and secondary dual approval."
        ))
        reasons.append(f"High-value transfer (${amount:,.2f}) mandates step-up MFA and supervisory review")

    # POL-007: Ambiguous Financial Intent Guard
    if ThreatCategory.AMBIGUOUS_INTENT in categories:
        if verdict != Verdict.BLOCK:
            verdict = Verdict.REVIEW
        violations.append(PolicyViolation(
            rule_id="POL-007",
            rule_name="Ambiguous Financial Intent Guard",
            description="User intent lacks concrete recipient or specific transaction boundaries.",
            required_action="Prompt user for explicit parameters before allowing privileged call."
        ))
        reasons.append("Ambiguous financial intent requires explicit user confirmation")

    if verdict == Verdict.APPROVE and not reasons:
        reasons.append("No security anomalies or adversarial patterns detected. Request within safe parameters.")

    return verdict, violations, reasons, requires_step_up
