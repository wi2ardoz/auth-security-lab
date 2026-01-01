"""
totp.py
TOTP (Time-based One-Time Password) validation for two-factor authentication.
"""

import pyotp
from . import defenses_const


def validate_totp_code(totp_secret: str, totp_code: str) -> bool:
    """
    Validate a TOTP code against the user's secret.
    Uses TOTP validation with configurable time window for clock skew 
    tolerance of TOTP_VALID_WINDOW seconds.

    Args:
        totp_secret: Base32-encoded TOTP secret key
        totp_code: 6-digit TOTP code provided by user

    Returns:
        True if code is valid within the time window, False otherwise
    """
    if not totp_secret or not totp_code:
        return False

    try:
        totp = pyotp.TOTP(totp_secret)
        return totp.verify(totp_code, valid_window=defenses_const.TOTP_VALID_WINDOW)
    except Exception:
        # Invalid secret format or verification error
        return False
