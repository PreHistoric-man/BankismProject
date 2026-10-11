"""Safe security logging configuration that intercepts and redacts sensitive banking data."""

import logging
import sys
from ..security.masking import mask_sensitive_data


class MaskingLogFilter(logging.Filter):
    """Logging filter that scrubs sensitive financial information from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = mask_sensitive_data(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: mask_sensitive_data(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(mask_sensitive_data(str(a)) for a in record.args)
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
