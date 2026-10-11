"""
PCI-DSS and GLBA Sensitive Financial Data Masking Module
"""
import re


# Credit/Debit Card PAN Pattern (13-19 digits, with optional spaces or dashes)
PAN_REGEX = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|(?:[0-9]{4}[-\s]){3}[0-9]{4}|[0-9]{16})\b"
)

# Social Security Number (SSN) Pattern
SSN_REGEX = re.compile(r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b")

# Bearer token and API key patterns
BEARER_TOKEN_REGEX = re.compile(r"\b(bearer\s+[A-Za-z0-9\-._~+/]+=*)\b", re.IGNORECASE)
SECRET_ASSIGN_REGEX = re.compile(r"\b(api[_-]?key|password|secret)\s*[:=]\s*['\"]?[^'\"\s]+['\"]?", re.IGNORECASE)


def mask_sensitive_data(text: str) -> str:
    """
    Redacts PAN card numbers, SSNs, and credentials before logging or recording in audit logs.
    """
    if not text:
        return ""

    def replace_pan(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        return f"****-****-****-{digits[-4:]}"

    def replace_ssn(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        return f"***-**-{digits[-4:]}"

    masked = PAN_REGEX.sub(replace_pan, text)
    masked = SSN_REGEX.sub(replace_ssn, masked)
    masked = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED_TOKEN]", masked)
    masked = SECRET_ASSIGN_REGEX.sub(r"\1: [REDACTED_SECRET]", masked)
    return masked
