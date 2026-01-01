"""
__init__.py
Defenses package initialization.
"""

from .account_lockout import (increment_failed_attempts, is_account_locked,
                              reset_failed_attempts)
from .captcha_manager import (generate_captcha_token, should_require_captcha,
                               validate_captcha_token)
from .defenses_const import HASH_ARGON2ID, HASH_BCRYPT, HASH_SHA256
from .hash import hash_password, verify_password
from .rate_limiter import check_rate_limit

__all__ = [
    "hash_password",
    "verify_password",
    "check_rate_limit",
    "is_account_locked",
    "increment_failed_attempts",
    "reset_failed_attempts",
    "should_require_captcha",
    "generate_captcha_token",
    "validate_captcha_token",
    "HASH_SHA256",
    "HASH_BCRYPT",
    "HASH_ARGON2ID",
]
