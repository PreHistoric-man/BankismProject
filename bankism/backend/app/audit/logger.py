"""Safe security logging configuration that intercepts and redacts sensitive banking data."""

import logging
import sys
from ..security.masking import mask_sensitive_data


import re

ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def sanitize_log_string(text: str) -> str:
    """Mask sensitive data, strip ANSI escape codes, and escape CRLF to prevent log injection (CWE-117)."""
    if not isinstance(text, str):
        text = str(text)
    # Mask PII and secrets
    masked = mask_sensitive_data(text)
    # Strip terminal ANSI escape codes
    cleaned = ANSI_ESCAPE_PATTERN.sub("", masked)
    # Neutralize CRLF newlines to prevent log forging
    cleaned = cleaned.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return cleaned


class MaskingLogFilter(logging.Filter):
    """Logging filter that scrubs sensitive financial information and neutralizes CRLF log injection."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_log_string(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: sanitize_log_string(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(sanitize_log_string(str(a)) for a in record.args)
        return True


def setup_security_logger(name: str = "bankism", level: int = logging.INFO) -> logging.Logger:
    """Create and configure a security-hardened logger with PII masking."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding duplicate handlers on multiple calls
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [BankismSecurity] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(MaskingLogFilter())
        logger.addHandler(handler)

    return logger


# Global logger instance
security_logger = setup_security_logger()
