"""
captcha.py
CAPTCHA token generation and validation for failed login attempts.
"""

import uuid
from typing import Dict

from database import get_auth_state

from . import defenses_const

# In-memory storage: token -> username
_captcha_tokens: Dict[str, str] = {}


def should_require_captcha(cursor, username: str) -> bool:
    """
    Check if user has reached the CAPTCHA threshold.

    Args:
        cursor: Database cursor
        username: Username to check

    Returns:
        True if CAPTCHA is required, False otherwise
    """
    auth_state = get_auth_state(cursor, username)

    if not auth_state:
        return False

    failed_attempts = auth_state[0]
    return failed_attempts >= defenses_const.CAPTCHA_THRESHOLD


def generate_captcha_token(username: str) -> str:
    """
    Generate a new CAPTCHA token for the user.
    Invalidates any existing tokens for this user (prevents token accumulation).

    Args:
        username: Username to generate token for

    Returns:
        UUID-based CAPTCHA token
    """
    # Invalidate old tokens for this user (prevent replay attacks)
    tokens_to_remove = [token for token, user in _captcha_tokens.items() if user == username]
    for token in tokens_to_remove:
        del _captcha_tokens[token]

    # Generate new token
    token = str(uuid.uuid4())
    _captcha_tokens[token] = username
    return token


def validate_captcha_token(username: str, token: str) -> bool:
    """
    Validate CAPTCHA token for the user.
    Consumes the token after usage.

    Args:
        username: Username attempting login
        token: CAPTCHA token to validate

    Returns:
        True if token is valid, False otherwise
    """
    if token not in _captcha_tokens or _captcha_tokens[token] != username:
        return False

    del _captcha_tokens[token]
    return True
