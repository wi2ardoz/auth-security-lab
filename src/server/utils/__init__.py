"""
__init__.py
Server utilities for configuration, logging, and helpers.
"""

from .cli import init_from_cli, parse_cli_args
from .config import get_hash_settings, load_config, save_config
from .logger import get_next_log_filename, init_log_file, log_attempt
from .utils_const import *

__all__ = [
    # Functions
    "init_from_cli",
    "parse_cli_args",
    "get_hash_settings",
    "load_config",
    "save_config",
    "get_next_log_filename",
    "init_log_file",
    "log_attempt",
    # Constants
    "SCHEME_KEY_HOST",
    "SCHEME_KEY_PORT",
    "SCHEME_KEY_HASH_MODE",
    "SCHEME_KEY_DEFENSES",
    "SCHEME_KEY_GROUP_SEED",
    "SCHEME_KEY_DEFENSE_RATE_LIMIT",
    "SCHEME_KEY_DEFENSE_LOCKOUT",
    "SCHEME_KEY_DEFENSE_CAPTCHA",
    "SCHEME_KEY_DEFENSE_TOTP",
    "SCHEME_KEY_DEFENSE_PEPPER",
]
