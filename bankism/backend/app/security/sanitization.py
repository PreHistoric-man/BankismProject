"""
Input Sanitization & Normalization Module
"""
import re
import unicodedata


# Zero-width spaces, soft hyphens, directional formatting marks
ZERO_WIDTH_REGEX = re.compile(
    r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u00AD\u2060-\u206F]"
)

# ASCII non-printable control characters (excluding newline \n, tab \t)
CONTROL_CHARS_REGEX = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def sanitize_input(text: str) -> str:
    """
    Applies Unicode NFKC canonicalization, strips dangerous zero-width characters,
    and removes non-printable control bytes.
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    stripped = ZERO_WIDTH_REGEX.sub("", normalized)
    cleaned = CONTROL_CHARS_REGEX.sub("", stripped)
    return cleaned.strip()


def detect_zero_width_evasion(raw_text: str) -> bool:
    """
    Returns True if invisible characters were found in the raw untrusted input.
    """
    if not raw_text:
        return False
    return bool(ZERO_WIDTH_REGEX.search(raw_text))
