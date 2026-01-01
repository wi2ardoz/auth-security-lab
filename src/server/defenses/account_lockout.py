"""
account_lockout.py
Account lockout after consecutive failed login attempts.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from database import get_auth_state, insert_auth_state, reset_auth_state, update_auth_state

from . import defenses_const


def is_account_locked(cursor, username: str) -> Tuple[bool, Optional[int]]:
    """
    Check if account is currently locked.

    Args:
        cursor: Database cursor
        username: Username to check

    Returns:
        Tuple of (locked, remaining_seconds):
            - locked: True if account is locked, False otherwise
            - remaining_seconds: Seconds until unlock (None if not locked)
    """
    auth_state = get_auth_state(cursor, username)

    if not auth_state or not auth_state[1]:
        return False, None

    locked_until = datetime.fromisoformat(auth_state[1])
    now = datetime.now(timezone.utc)

    if now < locked_until:
        # Still locked
        remaining = int((locked_until - now).total_seconds())
        return True, remaining
    else:
        # Lock expired
        return False, None


def increment_failed_attempts(
    cursor,
    username: str,
    lockout_threshold: int = defenses_const.LOCKOUT_THRESHOLD,
    lockout_duration: int = defenses_const.LOCKOUT_DURATION,
) -> bool:
    """
    Increment failed login attempts counter and lock account if threshold reached.

    Args:
        cursor: Database cursor
        username: Username to increment
        lockout_threshold: Number of failures before lockout
        lockout_duration: Lockout duration in seconds

    Returns:
        True if account was just locked, False otherwise
    """
    auth_state = get_auth_state(cursor, username)

    if auth_state:
        # User exists in auth_state
        current_attempts = auth_state[0]
        new_attempts = current_attempts + 1

        if new_attempts >= lockout_threshold:
            # Lock the account
            locked_until = datetime.now(timezone.utc) + timedelta(
                seconds=lockout_duration
            )
            update_auth_state(cursor, username, new_attempts, locked_until.isoformat())
            return True
        else:
            # Increment counter
            update_auth_state(cursor, username, new_attempts, locked_until=None)
            return False
    else:
        # First failed attempt - insert new record
        insert_auth_state(cursor, username, failed_attempts=1)
        return False


def reset_failed_attempts(cursor, username: str):
    """
    Reset failed attempts counter to 0 and clear lockout.
    Called on successful login.

    Args:
        cursor: Database cursor
        username: Username to reset
    """
    reset_auth_state(cursor, username)
