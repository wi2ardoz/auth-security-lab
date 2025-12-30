"""
logger.py
Logging utilities for authentication attempts.
"""

import json
import os
from datetime import datetime, timezone

import server_const as const

from . import utils_const


def get_next_log_filename(config):
    """
    Find next available log filename with numeric suffix if needed.
    Checks for existing files and increments: attempts, attempts2, attempts3, ...

    :param config: Server configuration dictionary
    :return: Full path to next available log file
    """
    base_filename = _get_log_filename_base(config)
    log_dir = const.LOG_DIR

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)

    # Check if base filename exists
    base_path = os.path.join(log_dir, base_filename)
    if not os.path.exists(base_path):
        return base_path

    # Find next available numeric suffix
    name_without_ext = base_filename.rsplit(".log", 1)[0]
    suffix = 2

    while True:
        new_filename = f"attempts{suffix}_{name_without_ext.split('_', 1)[1]}.log"
        new_path = os.path.join(log_dir, new_filename)

        if not os.path.exists(new_path):
            return new_path

        suffix += 1


def init_log_file(log_filepath):
    """
    Initialize log file. Creates directory and empty file if needed.

    :param log_filepath: Full path to log file
    """
    log_dir = os.path.dirname(log_filepath)
    os.makedirs(log_dir, exist_ok=True)

    # Create empty file if doesn't exist
    if not os.path.exists(log_filepath):
        with open(log_filepath, "w") as f:
            pass  # Create empty file


def log_attempt(log_filepath, username, result, latency_ms, config, 
    failure_reason=None, retry_after=None):
    """
    Log a single authentication attempt as JSON line.

    :param log_filepath: Full path to log file
    :param username: Username attempted
    :param result: "success" or "failure"
    :param latency_ms: Request latency in milliseconds
    :param config: Server configuration dictionary
    :param failure_reason: Optional reason for failure (rate_limited, invalid_credentials, etc.)
    :param retry_after: Optional seconds until retry allowed (for rate limiting)
    """
    timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    log_entry = {
        "timestamp": timestamp,
        "username": username,
        "hash_mode": config[utils_const.SCHEME_KEY_HASH_MODE],
        "protection_flags": config[utils_const.SCHEME_KEY_DEFENSES].copy(),
        "result": result,
        "latency_ms": round(latency_ms, 2),
        "group_seed": config[utils_const.SCHEME_KEY_GROUP_SEED],
    }

    # Add optional fields if provided
    if failure_reason is not None:
        log_entry["failure_reason"] = failure_reason
    if retry_after is not None:
        log_entry["retry_after"] = round(retry_after, 2)

    # Append as single JSON line
    with open(log_filepath, "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def _get_active_defenses(config):
    """
    Extract list of enabled defense mechanisms from config.

    :param config: Server configuration dictionary
    :return: Sorted list of enabled defense names
    """
    defenses = config[utils_const.SCHEME_KEY_DEFENSES]
    active = []

    for defense_key in utils_const.SCHEME_DEFENSE_KEYS:
        if defenses.get(defense_key, False):
            active.append(defense_key)

    return sorted(active)


def _get_log_filename_base(config):
    """
    Generate base log filename from configuration (without numeric suffix).
    Format: attempts_{hash}_{defense1}_{defense2}.log

    :param config: Server configuration dictionary
    :return: Base log filename
    """
    hash_mode = config[utils_const.SCHEME_KEY_HASH_MODE]
    active_defenses = _get_active_defenses(config)

    if active_defenses:
        defenses_str = "_".join(active_defenses)
        return f"attempts_{hash_mode}_{defenses_str}.log"
    else:
        return f"attempts_{hash_mode}_none.log"
