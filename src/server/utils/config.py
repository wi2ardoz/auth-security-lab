"""
config.py
Configuration management utilities.
Functions for loading/saving server JSON configuration file.
"""

import json
import os

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
    required_fields = ["host", "port", "hash_mode", "defenses", "pepper_value", "group_seed"]
    for field in required_fields:
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
    default_config = {
        "host": "0.0.0.0",
        "port": 8000,
        "hash_mode": "sha256",
        "defenses": {
            "rate_limit": "false",
            "lockout": "false",
            "captcha": "false",
            "totp": "false",
            "pepper": "false",
        },
        "pepper_value": "",
        "group_seed": "519933725",
    }
    return default_config
