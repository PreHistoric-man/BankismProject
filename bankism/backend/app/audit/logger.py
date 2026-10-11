"""
Structured and Masked Logging Handler
"""
import logging
from ..security.masking import mask_sensitive_data
from ..config import settings


logger = logging.getLogger("bankism")
logger.setLevel(logging.INFO)

# Avoid duplicate handlers
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [Bankism] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def log_security_event(event_type: str, user_id: str, message: str) -> None:
    """
    Emits a sanitized and masked security log line.
    """
    safe_msg = mask_sensitive_data(message) if settings.mask_log_sensitive_data else message
    safe_msg = safe_msg.replace("\n", " ").replace("\r", " ")
    logger.info(f"EVENT={event_type} USER={user_id} MSG={safe_msg}")
