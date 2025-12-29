"""
setup_db.py
Populate database with users from users.json using current server configuration.

This script:
    1. Reads current hash mode from server_config.json
    2. Loads users from users.json
    3. Clears the database
    4. Hashes passwords with current configuration
    5. Inserts users into database

Usage:
    python src/server/setup_db.py

Note:
    This can run while the server is running (SQLite allows concurrent access).
    The server must have been started at least once to generate server_config.json.
"""

import json
import sys
from pathlib import Path

import server_const as const
from database import clear_auth_state_table, clear_users_table, init_database, insert_user
from defenses import hash_password
from utils import get_hash_settings, load_config


def load_users_from_json(json_path):
    """
    Load users from users.json.

    :param json_path: Path to users.json file
    :return: List of user dictionaries
    :raises FileNotFoundError: If users.json doesn't exist
    :raises json.JSONDecodeError: If users.json is invalid JSON
    """
    if not Path(json_path).exists():
        raise FileNotFoundError(f"Users file not found: {json_path}")

    with open(json_path, "r") as f:
        data = json.load(f)

    if "users" not in data:
        raise ValueError(f"Invalid users.json: missing 'users' key")

    return data["users"]


def populate_database(users, hash_mode, pepper):
    """
    Populate database with users using specified hash configuration.

    :param users: List of user dictionaries from users.json
    :param hash_mode: Hash mode to use (sha256, bcrypt, argon2id)
    :param pepper: Pepper value (or None if disabled)
    :return: Tuple (success_count, fail_count, category_counts)
    """
    success_count = 0
    fail_count = 0

    # Track counts by category
    category_counts = {"weak": 0, "medium": 0, "strong": 0}

    for user in users:
        username = user["username"]
        password = user["password"]
        totp_secret = user.get("totp_secret")
        category = user.get("category", "unknown")

        try:
            # Hash the password with current configuration
            password_hash, salt = hash_password(
                password, hash_mode, salt=None, pepper=pepper
            )

            # Insert into database
            if insert_user(username, password_hash, salt, totp_secret):
                success_count += 1
                if category in category_counts:
                    category_counts[category] += 1
                print(f"  ✓ {username:10s} ({category:6s})")
            else:
                fail_count += 1
                print(f"  ✗ {username:10s} - Username already exists")

        except Exception as e:
            fail_count += 1
            print(f"  ✗ {username:10s} - Error: {e}")

    return success_count, fail_count, category_counts


def print_summary(
    success_count, fail_count, total_count, category_counts, hash_mode, pepper
):
    """Print summary of database seeding operation."""
    print("\n" + "=" * 70)
    print("Summary:")
    print(f"  Total users:        {total_count}")
    print(f"  Successfully added: {success_count}")
    print(f"  Failed:             {fail_count}")
    print()
    print(f"  By category:")
    print(f"    Weak:   {category_counts.get('weak', 0)}")
    print(f"    Medium: {category_counts.get('medium', 0)}")
    print(f"    Strong: {category_counts.get('strong', 0)}")
    print()
    print(f"  Configuration:")
    print(f"    Hash mode: {hash_mode}")
    print(f"    Pepper:    {'enabled' if pepper else 'disabled'}")
    print("=" * 70)


def main():
    # Initialize database (create table if needed)
    init_database()
    print("\n✓ Database initialized")

    # Load server configuration
    try:
        config = load_config(const.CONFIG_PATH)
        print(f"✓ Loaded configuration from {const.CONFIG_PATH}")
    except FileNotFoundError:
        print(f"\n✗ Error: Configuration file not found: {const.CONFIG_PATH}")
        print("  Please run the server at least once to generate default config:")
        print(f"    python src/server/server.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error loading configuration: {e}")
        sys.exit(1)

    # Extract hash settings from config
    hash_mode, pepper = get_hash_settings(config)

    # Load users from JSON
    try:
        users = load_users_from_json(const.USERS_JSON_PATH)
        print(f"✓ Loaded {len(users)} users from {const.USERS_JSON_PATH}")
    except FileNotFoundError:
        print(f"\n✗ Error: Users file not found: {const.USERS_JSON_PATH}")
        print("  Please ensure users.json exists with test accounts.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"\n✗ Error: Invalid JSON in users file: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)

    # Clear existing database
    print(f"\n⚠ Clearing existing database...")
    try:
        clear_users_table()
        clear_auth_state_table()
        print("✓ Database cleared (users + auth_state)")
    except Exception as e:
        print(f"✗ Error clearing database: {e}")
        sys.exit(1)

    # Populate database
    print(f"\nPopulating database with {hash_mode} hashes...")
    success_count, fail_count, category_counts = populate_database(
        users, hash_mode, pepper
    )

    # Print summary
    print_summary(
        success_count, fail_count, len(users), category_counts, hash_mode, pepper
    )

    # Exit with error code if any failures
    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
