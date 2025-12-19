"""
config.py
Configuration management utilities.
Functions for loading/saving server JSON configuration file.
"""

import json
import os

from . import utils_const as const

JSON_INDENT = 4


def load_config(config_path):
    """
    Load configuration from a JSON file.

    :param config_path: Path to the configuration file
    :return: Configuration dictionary
    :raises FileNotFoundError: If config file doesn't exist
    :raises json.JSONDecodeError: If config file is invalid JSON
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as f:
        config = json.load(f)

    # Validate required fields for server config
    for field in const.SCHEME_REQUIRED_KEYS:
        if field not in config:
            raise ValueError(f"Missing required field in config: {field}")

    return config


def save_config(config, config_path):
    """
    Save configuration to a JSON file.

    :param config: Configuration dictionary to save
    :param config_path: Path where to save the configuration
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    # Write config with pretty formatting
    with open(config_path, "w") as f:
        json.dump(config, f, indent=JSON_INDENT)


def get_default_config():
    """
    Get the default server configuration.
    Should be used only when no config file is found.
    NOTE This default config uses no defenses.

    :return: Default configuration dictionary
    """
    return {
        const.SCHEME_KEY_HOST: const.SCHEME_VALUE_HOST_DEFAULT,
        const.SCHEME_KEY_PORT: const.SCHEME_VALUE_PORT_DEFAULT,
        const.SCHEME_KEY_HASH_MODE: const.SCHEME_VALUE_HASH_MODE_DEFAULT,
        const.SCHEME_KEY_DEFENSES: {
            const.SCHEME_KEY_DEFENSE_RATE_LIMIT: const.SCHEME_VALUE_DEFENSE_RATE_LIMIT_DEFAULT,
            const.SCHEME_KEY_DEFENSE_LOCKOUT: const.SCHEME_VALUE_DEFENSE_LOCKOUT_DEFAULT,
            const.SCHEME_KEY_DEFENSE_CAPTCHA: const.SCHEME_VALUE_DEFENSE_CAPTCHA_DEFAULT,
            const.SCHEME_KEY_DEFENSE_TOTP: const.SCHEME_VALUE_DEFENSE_TOTP_DEFAULT,
            const.SCHEME_KEY_DEFENSE_PEPPER: const.SCHEME_VALUE_DEFENSE_PEPPER_DEFAULT,
        },
        const.SCHEME_KEY_PEPPER_VALUE: const.SCHEME_VALUE_PEPPER_DEFAULT,
        const.SCHEME_KEY_GROUP_SEED: const.SCHEME_VALUE_GROUP_SEED_DEFAULT,
    }


def get_hash_settings(config):
    """
    Get hash mode and pepper settings from config.
    :return: Tuple of (hash_mode, pepper)
    """
    hash_mode = config[const.SCHEME_KEY_HASH_MODE]

    pepper_enabled = config[const.SCHEME_KEY_DEFENSES][const.SCHEME_KEY_DEFENSE_PEPPER]
    pepper = config[const.SCHEME_KEY_PEPPER_VALUE] if pepper_enabled else None

    return hash_mode, pepper
