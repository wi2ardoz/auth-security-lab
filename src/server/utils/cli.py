"""
cli.py
Command-line argument parsing for authentication server.
"""

import argparse

from . import utils_const as const
from .config import get_default_config, load_config, save_config


def parse_cli_args():
    """
    Parse command-line arguments for server configuration.

    :return: Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Authentication Server - FastAPI + SQLite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Hash mode
    parser.add_argument(
        "--hash",
        choices=["sha256", "bcrypt", "argon2id"],
        help="Hash algorithm (sha256 | bcrypt | argon2id)",
    )

    # Defense flags
    parser.add_argument(
        "--rate-limit", action="store_true", help="Enable rate limiting"
    )
    parser.add_argument("--lockout", action="store_true", help="Enable account lockout")
    parser.add_argument(
        "--captcha", action="store_true", help="Enable CAPTCHA simulation"
    )
    parser.add_argument("--totp", action="store_true", help="Enable TOTP requirement")
    parser.add_argument("--pepper", action="store_true", help="Enable pepper")

    # Server settings
    parser.add_argument("--port", type=int, help="Server port (default: from config)")

    return parser.parse_args()


def init_from_cli(config_path, args):
    """
    Initialize server configuration from file and CLI arguments.
    Loads config, applies CLI overrides, saves if modified.
    This is the main entry point for CLI-based configuration.

    :param config_path: Path to configuration file
    :param args: Parsed command-line arguments
    :return: Configuration dictionary
    """
    # Load or create config
    try:
        config = load_config(config_path)
        print(f"✓ Loaded configuration from {config_path}")
    except FileNotFoundError:
        print(f"⚠ Config file not found: {config_path}")
        print(f"  Creating default configuration...")
        config = get_default_config()
        save_config(config, config_path)
        print(f"✓ Created default config at {config_path}")

    # Merge CLI arguments
    config, modified = merge_cli_into_config(config, args)

    # Save if modified
    if modified:
        save_config(config, config_path)
        print(f"✓ Updated configuration saved to {config_path}")

    # Display active config
    defenses = config[const.SCHEME_KEY_DEFENSES]
    defenses_list = [k for k, v in defenses.items() if v] or "None"
    print(f"  Hash: {config[const.SCHEME_KEY_HASH_MODE]}, Defenses: {defenses_list}")

    return config


def merge_cli_into_config(config, args):
    """
    Merge command-line arguments into configuration.

    Rules:
    - If --hash provided: Update hash, clear all defenses
    - If any defense flag provided: Enable only those defenses
    - If --port provided: Update this value
    - No args: Use config as-is

    :param config: Configuration dictionary
    :param args: Parsed command-line arguments
    :return: Tuple (Updated configuration dictionary, was_modified)
    """
    # Track if any CLI args were provided
    config_modified = False

    # Update hash mode
    if args.hash is not None:
        config[const.SCHEME_KEY_HASH_MODE] = args.hash
        # Clear all defenses when hash changes (explicit experiment)
        config[const.SCHEME_KEY_DEFENSES] = {
            const.SCHEME_KEY_DEFENSE_RATE_LIMIT: False,
            const.SCHEME_KEY_DEFENSE_LOCKOUT: False,
            const.SCHEME_KEY_DEFENSE_CAPTCHA: False,
            const.SCHEME_KEY_DEFENSE_TOTP: False,
            const.SCHEME_KEY_DEFENSE_PEPPER: False,
        }
        config_modified = True

    # Check if any defense flag was provided
    defense_flags_provided = any(
        [
            args.rate_limit,
            args.lockout,
            args.captcha,
            args.totp,
            args.pepper,
        ]
    )

    # If defense flags provided, set explicitly
    if defense_flags_provided:
        config[const.SCHEME_KEY_DEFENSES] = {
            const.SCHEME_KEY_DEFENSE_RATE_LIMIT: args.rate_limit,
            const.SCHEME_KEY_DEFENSE_LOCKOUT: args.lockout,
            const.SCHEME_KEY_DEFENSE_CAPTCHA: args.captcha,
            const.SCHEME_KEY_DEFENSE_TOTP: args.totp,
            const.SCHEME_KEY_DEFENSE_PEPPER: args.pepper,
        }
        config_modified = True

    # Update port if provided
    if args.port is not None:
        config[const.SCHEME_KEY_PORT] = args.port
        config_modified = True

    return config, config_modified
