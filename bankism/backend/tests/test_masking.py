"""Unit tests for sensitive data masking and redaction."""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.security.masking import mask_banking_dict, mask_sensitive_data


def test_mask_credit_cards():
    """Verify various credit card number formats are masked properly."""
    cards = [
        "4111222233334444",
        "4111-2222-3333-4444",
        "4111 2222 3333 4444",
        "5500 0000 0000 1234",
    ]
    for card in cards:
        result = mask_sensitive_data(f"Use card {card} for checkout")
        assert card not in result
        assert "1234" in result or "4444" in result
        assert "****" in result


def test_mask_social_security_numbers():
    """Verify SSNs are masked."""
    sample = "Customer SSN is 123-45-6789 for tax identification"
    result = mask_sensitive_data(sample)
    assert "123-45-6789" not in result
    assert "***-**-6789" in result


def test_mask_bank_accounts():
    """Verify bank account numbers following keywords are masked."""
    sample = "Please wire to account number: 987654321012 immediately"
    result = mask_sensitive_data(sample)
    assert "987654321012" not in result
    assert "1012" in result
    assert "*****" in result


def test_mask_auth_tokens_and_passwords():
    """Verify API keys, bearer tokens, passwords are redacted."""
    sample = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz and password=MySecretPassword123!"
    result = mask_sensitive_data(sample)
    assert "eyJhbGciOi" not in result
    assert "MySecretPassword123!" not in result
    assert "[REDACTED_TOKEN]" in result
    assert "[REDACTED_SECRET]" in result


def test_mask_banking_dict_nested():
    """Verify dictionary scrubber handles nested objects and sensitive keys."""
    raw = {
        "user": "Alice",
        "password": "supersecretpassword",
        "pin": "1234",
        "nested": {
            "card_number": "4111222233334444",
            "memo": "Payment with SSN 123-45-6789",
        },
        "tags": ["normal", "api_key=sk-live-998877"],
    }
    masked = mask_banking_dict(raw)
    assert masked["password"] == "[REDACTED_CONFIDENTIAL]"
    assert masked["pin"] == "[REDACTED_CONFIDENTIAL]"
    assert masked["nested"]["card_number"] == "[REDACTED_CONFIDENTIAL]"
    assert "123-45-6789" not in masked["nested"]["memo"]
    assert "***-**-6789" in masked["nested"]["memo"]
