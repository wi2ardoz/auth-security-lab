"""
account_lockout.py
Account lockout after consecutive failed login attempts.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

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
    cursor.execute(
        """
        SELECT locked_until FROM auth_state WHERE username = ?
        """,
        (username,),
    )
    result = cursor.fetchone()

    if not result or not result[0]:
        return False, None

    locked_until = datetime.fromisoformat(result[0])
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
    # Get current failed attempts
    cursor.execute(
        """
        SELECT failed_attempts FROM auth_state WHERE username = ?
        """,
        (username,),
    )
    result = cursor.fetchone()

    if result:
        # User exists in auth_state
        current_attempts = result[0]
        new_attempts = current_attempts + 1

        if new_attempts >= lockout_threshold:
            # Lock the account
            locked_until = datetime.now(timezone.utc) + timedelta(
                seconds=lockout_duration
            )
            cursor.execute(
                """
                UPDATE auth_state
                SET failed_attempts = ?, locked_until = ?
                WHERE username = ?
                """,
                (new_attempts, locked_until.isoformat(), username),
            )
            return True
        else:
            # Increment counter
            cursor.execute(
                """
                UPDATE auth_state
                SET failed_attempts = ?
                WHERE username = ?
                """,
                (new_attempts, username),
            )
            return False
    else:
        # First failed attempt - insert new record
        cursor.execute(
            """
            INSERT INTO auth_state (username, failed_attempts)
            VALUES (?, 1)
            """,
            (username,),
        )
        return False


def reset_failed_attempts(cursor, username: str):
    """
    Reset failed attempts counter to 0 and clear lockout.
    Called on successful login.

    Args:
        cursor: Database cursor
        username: Username to reset
    """
    cursor.execute(
        """
        UPDATE auth_state
        SET failed_attempts = 0, locked_until = NULL
        WHERE username = ?
        """,
        (username,),
    )
    # Insert if not exists
    if cursor.rowcount == 0:
        cursor.execute(
            """
            INSERT INTO auth_state (username, failed_attempts, locked_until)
            VALUES (?, 0, NULL)
            """,
            (username,),
        )
