"""Concrete security rules for the Bankism policy engine."""

from typing import List, Optional, Tuple
from ..schemas.common import RiskLevel, ThreatCategory, Verdict
from ..schemas.firewall import PolicyViolation, ProposedOperation, ThreatDetail


class PolicyRule:
    """Base class for firewall governance rules."""

    rule_id: str
    rule_name: str
    description: str

    def evaluate(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation],
        high_amount_threshold: float = 10000.0,
    ) -> Tuple[Optional[Verdict], Optional[RiskLevel], Optional[PolicyViolation], Optional[str], bool]:
        """Evaluate rule conditions.

        Returns:
            Tuple of:
            - verdict_override: Optional[Verdict]
            - risk_level_override: Optional[RiskLevel]
            - violation: Optional[PolicyViolation]
            - reason: Optional[str]
            - requires_step_up: bool
        """
        raise NotImplementedError


class PromptInjectionRule(PolicyRule):
    """Enforces zero-tolerance blocking of adversarial prompt injections."""

    rule_id = "POL-001"
    rule_name = "Zero-Tolerance Prompt Injection Defense"
    description = "Immediate block for requests attempting to override system instructions or hijack LLM personas."

    def evaluate(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation],
        high_amount_threshold: float = 10000.0,
    ) -> Tuple[Optional[Verdict], Optional[RiskLevel], Optional[PolicyViolation], Optional[str], bool]:
        has_injection = any(t.category == ThreatCategory.PROMPT_INJECTION for t in threats)
        if has_injection:
            violation = PolicyViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description="Adversarial prompt injection pattern detected in untrusted user input.",
                required_action="Reject request and log security alert.",
            )
            return Verdict.BLOCK, RiskLevel.CRITICAL, violation, "Prompt injection attempt detected", False
        return None, None, None, None, False


class JailbreakRule(PolicyRule):
    """Enforces immediate blocking of jailbreak attempts."""

    rule_id = "POL-002"
    rule_name = "LLM Jailbreak Block Rule"
    description = "Immediate block for roleplay, hypothetical bypasses, or safety avoidance vectors."

    def evaluate(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation],
        high_amount_threshold: float = 10000.0,
    ) -> Tuple[Optional[Verdict], Optional[RiskLevel], Optional[PolicyViolation], Optional[str], bool]:
        has_jailbreak = any(t.category == ThreatCategory.JAILBREAK_ATTEMPT for t in threats)
        if has_jailbreak:
            violation = PolicyViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description="Jailbreak or guardrail bypass phrase matched in incoming message.",
                required_action="Reject request immediately.",
            )
            return Verdict.BLOCK, RiskLevel.CRITICAL, violation, "Jailbreak attempt detected", False
        return None, None, None, None, False


class MaliciousMetadataRule(PolicyRule):
    """Blocks any payment metadata containing injection payloads (SQLi, XSS, Cmd)."""

    rule_id = "POL-003"
    rule_name = "Malicious Payment Metadata Quarantine"
    description = "Blocks requests attempting to inject SQL, script tags, or shell commands in financial payloads."

    def evaluate(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation],
        high_amount_threshold: float = 10000.0,
    ) -> Tuple[Optional[Verdict], Optional[RiskLevel], Optional[PolicyViolation], Optional[str], bool]:
        has_metadata_attack = any(t.category == ThreatCategory.MALICIOUS_PAYMENT_METADATA for t in threats)
        if has_metadata_attack:
            violation = PolicyViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description="Malicious payload syntax found in payment reference, memo, or account fields.",
                required_action="Quarantine transaction and block request.",
            )
            return Verdict.BLOCK, RiskLevel.CRITICAL, violation, "Malicious payment metadata detected", False
        return None, None, None, None, False


class ObfuscationRule(PolicyRule):
    """Blocks or flags obfuscated inputs using invisible chars or evasion tactics."""

    rule_id = "POL-004"
    rule_name = "Adversarial Obfuscation Gate"
    description = "Guards against zero-width unicode, leetspeak, or base64 evasion vectors."

    def evaluate(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation],
        high_amount_threshold: float = 10000.0,
    ) -> Tuple[Optional[Verdict], Optional[RiskLevel], Optional[PolicyViolation], Optional[str], bool]:
        obf_threats = [t for t in threats if t.category == ThreatCategory.OBFUSCATION]
        if obf_threats:
            max_conf = max(t.confidence for t in obf_threats)
            is_critical = max_conf >= 0.7
            verdict = Verdict.BLOCK if is_critical else Verdict.REVIEW
            risk_level = RiskLevel.HIGH if is_critical else RiskLevel.MEDIUM
            violation = PolicyViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description="Input utilizes suspicious obfuscation or evasion techniques.",
                required_action="Block request if high confidence; otherwise route to human security review.",
            )
            return verdict, risk_level, violation, "Suspicious input obfuscation detected", not is_critical
        return None, None, None, None, False


class InvalidInputRule(PolicyRule):
    """Rejects empty, malformed, or binary-filled input."""

    rule_id = "POL-005"
    rule_name = "Malformed Input Hygiene Rule"
    description = "Rejects requests that fail schema, whitespace, or control character validation."

    def evaluate(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation],
        high_amount_threshold: float = 10000.0,
    ) -> Tuple[Optional[Verdict], Optional[RiskLevel], Optional[PolicyViolation], Optional[str], bool]:
        has_invalid = any(t.category == ThreatCategory.INVALID_INPUT for t in threats)
        if has_invalid:
            violation = PolicyViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description="Request input is malformed, empty, or unparseable.",
                required_action="Return deterministic BLOCK verdict.",
            )
            return Verdict.BLOCK, RiskLevel.HIGH, violation, "Invalid or malformed input", False
        return None, None, None, None, False


class HighAmountThresholdRule(PolicyRule):
    """Requires step-up authentication and review for large financial amounts."""

    rule_id = "POL-006"
    rule_name = "High-Value Transaction Step-Up Policy"
    description = "Mandates multi-factor authentication and review for transfers exceeding threshold."

    def evaluate(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation],
        high_amount_threshold: float = 10000.0,
    ) -> Tuple[Optional[Verdict], Optional[RiskLevel], Optional[PolicyViolation], Optional[str], bool]:
        if operation and operation.amount is not None:
            if operation.amount >= high_amount_threshold:
                violation = PolicyViolation(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    description=f"Transaction amount ${operation.amount:,.2f} exceeds standard limit (${high_amount_threshold:,.2f}).",
                    required_action="Mandate out-of-band Step-Up MFA authentication and supervisory review.",
                )
                return (
                    Verdict.REVIEW,
                    RiskLevel.HIGH,
                    violation,
                    f"High-value transfer (${operation.amount:,.2f}) requires supervisory review and step-up auth",
                    True,
                )
        return None, None, None, None, False


class AmbiguousIntentRule(PolicyRule):
    """Requires review and confirmation for ambiguous or unbounded financial intent."""

    rule_id = "POL-007"
    rule_name = "Ambiguous Financial Intent Guard"
    description = "Prevents privileged operations on vague or unbounded prompts."

    def evaluate(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation],
        high_amount_threshold: float = 10000.0,
    ) -> Tuple[Optional[Verdict], Optional[RiskLevel], Optional[PolicyViolation], Optional[str], bool]:
        has_ambiguous = any(t.category == ThreatCategory.AMBIGUOUS_INTENT for t in threats)
        if has_ambiguous:
            violation = PolicyViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description="User intent is vague, unbounded, or missing explicit beneficiary parameters.",
                required_action="Prompt user for explicit parameters before allowing privileged banking call.",
            )
            return (
                Verdict.REVIEW,
                RiskLevel.MEDIUM,
                violation,
                "Ambiguous financial intent requires explicit user confirmation",
                True,
            )
        return None, None, None, None, False
