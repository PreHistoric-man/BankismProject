"""Sensitive banking information masking and PCI-DSS / GLBA compliance redaction."""

import re
from typing import Any, Dict


# Credit/Debit Card pattern: 13 to 19 digits, optional dashes or spaces
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11}|(?:[0-9]{4}[-\s]){3}[0-9]{4}|[0-9]{16})\b"
)

# Social Security Number pattern: 3-2-4 digits formatted or contiguous 9 digits
SSN_PATTERN = re.compile(
    r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b"
)

# Bank Account Number: 8 to 17 digits preceded by keywords or common account formats
ACCOUNT_NUM_KEYWORD_PATTERN = re.compile(
    r"(?i)\b((?:account|acct)(?:\s+number|\s+no|\s*#)?\s*(?:is|:)?\s*)([0-9]{8,17})\b"
)
ACCOUNT_RAW_LONG_PATTERN = re.compile(
    r"\b(ACC-[A-Za-z0-9]+-)?([0-9]{8,12})\b"
)

# Authentication secrets, API keys, passwords, bearer tokens, OTP codes
AUTH_TOKEN_PATTERN = re.compile(
    r"(?i)\b(bearer\s+[A-Za-z0-9\-._~+/]+=*|(?:api[_-]?key|secret|password|passwd|auth[_-]?token|pin|otp)\s*(?:[:=]|\bis\b)\s*['\"]?([A-Za-z0-9\-._~+/!@#$%^&*]{3,128})['\"]?)"
)

# CVV / CVC (3 or 4 digits near cvv/cvc keyword)
CVV_PATTERN = re.compile(
    r"(?i)\b(cvv\d?|cvc|security\s+code)\s*[:=]?\s*([0-9]{3,4})\b"
)


def _mask_credit_card(match: re.Match) -> str:
    """Mask card number keeping only the last 4 digits."""
    val = match.group(0)
    digits = re.sub(r"\D", "", val)
    if len(digits) >= 12:
        last4 = digits[-4:]
        return f"****-****-****-{last4}"
    return "****"


def _mask_ssn(match: re.Match) -> str:
    """Mask SSN to ***-**-XXXX."""
    val = match.group(0)
    digits = re.sub(r"\D", "", val)
    if len(digits) == 9:
        return f"***-**-{digits[-4:]}"
    return "***-**-****"


def _mask_account_keyword(match: re.Match) -> str:
    """Mask account numbers following keywords."""
    prefix = match.group(1)
    acc = match.group(2)
    last4 = acc[-4:] if len(acc) >= 4 else acc
    return f"{prefix}*****{last4}"


def _mask_cvv(match: re.Match) -> str:
    prefix = match.group(1)
    return f"{prefix}: ***"


def _mask_token(match: re.Match) -> str:
    matched = match.group(0)
    if matched.lower().startswith("bearer "):
        return "Bearer [REDACTED_TOKEN]"
    # Extract the key name before the separator
    sep_match = re.search(r"[:=]|\bis\b", matched, flags=re.IGNORECASE)
    if sep_match:
        key_name = matched[:sep_match.end()]
        return f"{key_name} [REDACTED_SECRET]"
    return "[REDACTED_SECRET]"


def mask_sensitive_data(text: str) -> str:
    """Scrub sensitive financial and credential information from plain text.

    Args:
        text: Arbitrary string possibly containing PANs, SSNs, accounts, or tokens.

    Returns:
        Redacted string safe for persistence and audit logging.
    """
    if not text:
        return ""

    masked = text

    # 1. Mask Auth tokens and passwords first
    masked = AUTH_TOKEN_PATTERN.sub(_mask_token, masked)

    # 2. Mask CVVs
    masked = CVV_PATTERN.sub(_mask_cvv, masked)

    # 3. Mask Credit / Debit card numbers
    masked = CREDIT_CARD_PATTERN.sub(_mask_credit_card, masked)

    # 4. Mask SSNs
    masked = SSN_PATTERN.sub(_mask_ssn, masked)

    # 5. Mask Bank account numbers after keywords
    masked = ACCOUNT_NUM_KEYWORD_PATTERN.sub(_mask_account_keyword, masked)

    return masked


def mask_banking_dict(data: Dict[str, Any], max_depth: int = 15) -> Dict[str, Any]:
    """Recursively scrub sensitive keys and values in dictionary payloads."""
    if max_depth <= 0:
        return {"[REDACTED_DEPTH_LIMIT]": True}

    sensitive_keys = {
        "password",
        "pin",
        "otp",
        "secret",
        "token",
        "ssn",
        "cvv",
        "card_number",
        "pan",
        "api_key",
        "auth",
    }
    cleaned: Dict[str, Any] = {}
    for key, value in data.items():
        key_lower = str(key).lower()
        if any(s in key_lower for s in sensitive_keys):
            cleaned[key] = "[REDACTED_CONFIDENTIAL]"
        elif isinstance(value, str):
            cleaned[key] = mask_sensitive_data(value)
        elif isinstance(value, dict):
            cleaned[key] = mask_banking_dict(value, max_depth - 1)
        elif isinstance(value, list):
            cleaned[key] = [
                mask_banking_dict(item, max_depth - 1) if isinstance(item, dict)
                else (mask_sensitive_data(item) if isinstance(item, str) else item)
                for item in value
            ]
        else:
            cleaned[key] = value
    return cleaned
