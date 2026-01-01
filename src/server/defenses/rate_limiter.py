"""
rate_limiter.py
Per-user rate limiting with per-second and per-minute thresholds.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from . import defenses_const

# In-memory storage: username -> list of request timestamps
_rate_limit_history: Dict[str, List[datetime]] = {}


def check_rate_limit(
    username: str,
    per_second: int = defenses_const.RATE_LIMIT_PER_SECOND,
    per_minute: int = defenses_const.RATE_LIMIT_PER_MINUTE,
) -> Tuple[bool, Optional[float]]:
    """
    Check if user has exceeded rate limits.

    Args:
        username: Username to check
        per_second: Maximum requests per second
        per_minute: Maximum requests per minute

    Returns:
        Tuple of (allowed, retry_after):
            - allowed: True if request is allowed, False if rate limited
            - retry_after: Seconds to wait before retry (None if allowed)
    """
    now = datetime.now(timezone.utc)

    # Initialize history for new users
    if username not in _rate_limit_history:
        _rate_limit_history[username] = []

    # Clean old entries (older than 60 seconds)
    cutoff_time = now - timedelta(seconds=60)
    _rate_limit_history[username] = [
        ts for ts in _rate_limit_history[username] if ts > cutoff_time
    ]

    # Count requests in last second and last minute
    one_second_ago = now - timedelta(seconds=1)
    requests_last_second = sum(
        1 for ts in _rate_limit_history[username] if ts > one_second_ago
    )
    requests_last_minute = len(_rate_limit_history[username])

    # Check per-second limit
    if requests_last_second >= per_second:
        # Calculate retry_after (time until oldest request in last second expires)
        oldest_in_second = min(
            [ts for ts in _rate_limit_history[username] if ts > one_second_ago]
        )
        retry_after = 1.0 - (now - oldest_in_second).total_seconds()
        return False, max(0.0, retry_after)

    # Check per-minute limit
    if requests_last_minute >= per_minute:
        # Calculate retry_after (time until oldest request expires)
        oldest_in_minute = min(_rate_limit_history[username])
        retry_after = 60.0 - (now - oldest_in_minute).total_seconds()
        return False, max(0.0, retry_after)

    # Allowed - record this request
    _rate_limit_history[username].append(now)
    return True, None
