"""
simulator.py
Constants for simulator app.
"""

# Server settings
SERVER_HOST = "http://localhost"
SERVER_PORT = "8000"
DEFAULT_ENDPOINT = "/login"
TOTP_ENDPOINT = "/login_totp"

# Attack types
ATTACK_PASSWORD_SPRAYING = "password_spraying"
ATTACK_BRUTE_FORCE = "brute_force"

# Defense playbook scenarios
NO_DEFENSES = "no_defenses"
SHA256_HASHING = "sha256"
BCRYPT_HASHING = "bcrypt"
ARGON2ID_HASHING = "argon2id"
RATE_LIMIT = "rate_limit"
LOCKOUT = "lockout"

# Scenario names and descriptions
SCENARIO_NAME_NO_DEFENSES = "No Defenses - Baseline"
SCENARIO_DESC_NO_DEFENSES = "No security mechanisms enabled (plaintext passwords)"

SCENARIO_NAME_SHA256_HASHING = "Basic Hashing (SHA-256)"
SCENARIO_DESC_SHA256_HASHING = "SHA-256 hashing with salt"

SCENARIO_NAME_BCRYPT_HASHING = "Bcrypt Hashing"
SCENARIO_DESC_BCRYPT_HASHING = "Bcrypt adaptive hashing (cost=12)"

SCENARIO_NAME_STRONG_HASHING = "Strong Hashing (Argon2id)"
SCENARIO_DESC_STRONG_HASHING = "Argon2id memory-hard hashing"

SCENARIO_NAME_RATE_LIMIT = "Rate Limiting"
SCENARIO_DESC_RATE_LIMIT = "SHA-256 hashing + rate limiting"

SCENARIO_NAME_LOCKOUT = "Account Lockout"
SCENARIO_DESC_LOCKOUT = "SHA-256 hashing + account lockout after failed attempts"

SCENARIO_NAME_CAPTCHA = "CAPTCHA Challenge"
SCENARIO_DESC_CAPTCHA = "SHA-256 hashing + CAPTCHA verification"

SCENARIO_NAME_FULL_DEFENSES = "Full Security Suite"
SCENARIO_DESC_FULL_DEFENSES = "All defenses enabled (Argon2id + rate limit + lockout + pepper)"

# Server wait times
SERVER_STARTUP_WAIT = 3  # seconds to wait for server to start
SERVER_SHUTDOWN_WAIT = 2  # seconds to wait for server to shutdown

# Target users for brute force
DEFAULT_BRUTE_FORCE_TARGETS = ["user01", "user02", "user03"]

# Max attempts for testing
DEFAULT_MAX_ATTEMPTS = 50

# File paths
SERVER_CONFIG_PATH = "src/server/server_config.json"
SERVER_PATH = "src/server/server.py"
SETUP_DB_PATH = "src/server/setup_db.py"
FILE_USERS_DATA_PATH = "src/data/users.json"

# File names
SERVER_DIR_NAME = "server"
SERVER_FILE = "server.py"
SETUP_DB_FILE = "setup_db.py"

# Config keys (matching server_config.json structure)
CONFIG_KEY_HASH_MODE = "hash_mode"
CONFIG_KEY_DEFENSES = "defenses"
CONFIG_KEY_RATE_LIMIT = "rate_limit"
CONFIG_KEY_LOCKOUT = "lockout"
CONFIG_KEY_CAPTCHA = "captcha"
CONFIG_KEY_TOTP = "totp"
CONFIG_KEY_PEPPER = "pepper"

# JSON keys
JSON_KEY_USERS = "users"
JSON_KEY_USERNAME = "username"


SCENARIOS =  [
        {
            "name": SCENARIO_NAME_SHA256_HASHING,
            "config": {
                CONFIG_KEY_HASH_MODE: SHA256_HASHING,
                CONFIG_KEY_DEFENSES: {
                    CONFIG_KEY_RATE_LIMIT: False,
                    CONFIG_KEY_LOCKOUT: False,
                    CONFIG_KEY_CAPTCHA: False,
                    CONFIG_KEY_TOTP: False,
                    CONFIG_KEY_PEPPER: False
                }
            }
        },
        {
            "name": SCENARIO_NAME_BCRYPT_HASHING,
            "config": {
                CONFIG_KEY_HASH_MODE: BCRYPT_HASHING,
                CONFIG_KEY_DEFENSES: {
                    CONFIG_KEY_RATE_LIMIT: False,
                    CONFIG_KEY_LOCKOUT: False,
                    CONFIG_KEY_CAPTCHA: False,
                    CONFIG_KEY_TOTP: False,
                    CONFIG_KEY_PEPPER: False
                }
            }
        },
        {
            "name": SCENARIO_NAME_STRONG_HASHING,
            "config": {
                CONFIG_KEY_HASH_MODE: ARGON2ID_HASHING,
                CONFIG_KEY_DEFENSES: {
                    CONFIG_KEY_RATE_LIMIT: False,
                    CONFIG_KEY_LOCKOUT: False,
                    CONFIG_KEY_CAPTCHA: False,
                    CONFIG_KEY_TOTP: False,
                    CONFIG_KEY_PEPPER: False
                }
            }
        },
        {
            "name": SCENARIO_NAME_RATE_LIMIT,
            "config": {
                CONFIG_KEY_HASH_MODE: SHA256_HASHING,
                CONFIG_KEY_DEFENSES: {
                    CONFIG_KEY_RATE_LIMIT: True,
                    CONFIG_KEY_LOCKOUT: False,
                    CONFIG_KEY_CAPTCHA: False,
                    CONFIG_KEY_TOTP: False,
                    CONFIG_KEY_PEPPER: False
                }
            }
        },
        {
            "name": SCENARIO_NAME_LOCKOUT,
            "config": {
                CONFIG_KEY_HASH_MODE: SHA256_HASHING,
                CONFIG_KEY_DEFENSES: {
                    CONFIG_KEY_RATE_LIMIT: False,
                    CONFIG_KEY_LOCKOUT: True,
                    CONFIG_KEY_CAPTCHA: False,
                    CONFIG_KEY_TOTP: False,
                    CONFIG_KEY_PEPPER: False
                }
            }
        },
        {
            "name": SCENARIO_NAME_CAPTCHA,
            "config": {
                CONFIG_KEY_HASH_MODE: SHA256_HASHING,
                CONFIG_KEY_DEFENSES: {
                    CONFIG_KEY_RATE_LIMIT: False,
                    CONFIG_KEY_LOCKOUT: False,
                    CONFIG_KEY_CAPTCHA: True,
                    CONFIG_KEY_TOTP: False,
                    CONFIG_KEY_PEPPER: False
                }
            }
        },
        {
            "name": SCENARIO_NAME_FULL_DEFENSES,
            "config": {
                CONFIG_KEY_HASH_MODE: ARGON2ID_HASHING,
                CONFIG_KEY_DEFENSES: {
                    CONFIG_KEY_RATE_LIMIT: True,
                    CONFIG_KEY_LOCKOUT: True,
                    CONFIG_KEY_CAPTCHA: False,
                    CONFIG_KEY_TOTP: False,
                    CONFIG_KEY_PEPPER: True
                }
            }
        }
    ]
