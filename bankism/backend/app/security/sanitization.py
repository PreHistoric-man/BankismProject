"""Input sanitization, canonicalization, and anti-obfuscation checks."""

import unicodedata
import re
from typing import Dict, List, Tuple


# Invisible, zero-width, bidirectional override, and soft hyphen characters
INVISIBLE_CHARS_PATTERN = re.compile(
    r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u00AD\u2060-\u206F]"
)

# Control characters excluding normal newline and tab (\t, \n, \r)
DANGEROUS_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

# Base64 string chunk detector (chunks of base64 like aWdub3JlIGFsbCBwcmV2aW91cw==)
BASE64_SUSPECT_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b"
)


def sanitize_input(text: str, max_length: int = 4000) -> str:
    """Normalize and sanitize untrusted natural-language input.

    - Performs NFKC unicode normalization
    - Strips dangerous control characters and null bytes
    - Strips zero-width and invisible bypass characters
    - Truncates to max_length
    - Normalizes excessive whitespace
    """
    if not text:
        return ""

    # 1. Unicode NFKC normalization (turns composite homoglyphs into canonical forms)
    normalized = unicodedata.normalize("NFKC", text)

    # 2. Remove null bytes and dangerous ASCII control chars
    normalized = DANGEROUS_CONTROL_CHARS.sub("", normalized)

    # 3. Strip zero-width and invisible characters commonly used in LLM prompt injection evasion
    normalized = INVISIBLE_CHARS_PATTERN.sub("", normalized)

    # 4. Collapse multi-line carriage returns safely
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")

    # 5. Length safety check
    if len(normalized) > max_length:
        normalized = normalized[:max_length]

    return normalized.strip()


def check_obfuscation_indicators(text: str) -> Tuple[bool, List[str], float]:
    """Check if the text exhibits signs of deliberate evasion or obfuscation.

    Returns:
        (is_obfuscated, list_of_reasons, obfuscation_score)
    """
    reasons: List[str] = []
    score: float = 0.0

    # 1. Check for invisible characters in raw text
    invisible_matches = INVISIBLE_CHARS_PATTERN.findall(text)
    if invisible_matches:
        reasons.append(f"Detected {len(invisible_matches)} invisible/zero-width character(s)")
        score += min(0.5, len(invisible_matches) * 0.15)

    # 2. Check for null bytes or control characters
    control_matches = DANGEROUS_CONTROL_CHARS.findall(text)
    if control_matches:
        reasons.append(f"Detected {len(control_matches)} dangerous control/null byte(s)")
        score += 0.6

    # 3. Check for high density of base64 encoded chunks
    b64_matches = BASE64_SUSPECT_PATTERN.findall(text)
    if b64_matches:
        reasons.append(f"Detected {len(b64_matches)} potential base64-encoded string payload(s)")
        score += min(0.6, len(b64_matches) * 0.3)

    # 4. Check for high non-ASCII or symbol density in short prompts
    if len(text) > 10:
        symbol_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / len(text)
        if symbol_ratio > 0.45:
            reasons.append(f"Unusually high symbol-to-text density ({symbol_ratio:.1%})")
            score += 0.4

    # 5. Check for repeated leetspeak or character spaced evasion (e.g., 'i g n o r e   a l l')
    spaced_words = re.findall(r"\b(?:[a-zA-Z]\s+){4,}[a-zA-Z]\b", text)
    if spaced_words:
        reasons.append("Detected deliberate character-spaced word evasion pattern")
        score += 0.5

    is_obfuscated = len(reasons) > 0 and score >= 0.35
    normalized_score = min(1.0, score)
    return is_obfuscated, reasons, normalized_score
