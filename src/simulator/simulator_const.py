"""
simulator.py
Constants for simulator app.
"""

# Attack types
ATTACK_PASSWORD_SPRAYING = "password_spraying"
ATTACK_BRUTE_FORCE = "brute_force"

# Defense playbook scenarios
SCENARIO_NO_DEFENSES = "no_defenses"
SCENARIO_BASIC_HASHING = "basic_hashing"
SCENARIO_STRONG_HASHING = "strong_hashing"
SCENARIO_RATE_LIMIT = "rate_limit"
SCENARIO_LOCKOUT = "lockout"
SCENARIO_FULL_DEFENSES = "full_defenses"
SCENARIO_ALL = "all"

# Scenario names and descriptions
SCENARIO_NAME_NO_DEFENSES = "No Defenses - Baseline"
SCENARIO_DESC_NO_DEFENSES = "No security mechanisms enabled (plaintext passwords)"

SCENARIO_NAME_BASIC_HASHING = "Basic Hashing (SHA-256)"
SCENARIO_DESC_BASIC_HASHING = "SHA-256 hashing with salt"

SCENARIO_NAME_STRONG_HASHING = "Strong Hashing (Argon2id)"
SCENARIO_DESC_STRONG_HASHING = "Argon2id memory-hard hashing"

SCENARIO_NAME_RATE_LIMIT = "Rate Limiting"
SCENARIO_DESC_RATE_LIMIT = "SHA-256 hashing + rate limiting"

SCENARIO_NAME_LOCKOUT = "Account Lockout"
SCENARIO_DESC_LOCKOUT = "SHA-256 hashing + account lockout after failed attempts"

SCENARIO_NAME_FULL_DEFENSES = "Full Security Suite"
SCENARIO_DESC_FULL_DEFENSES = "All defenses enabled (Argon2id + rate limit + lockout + pepper)"

# Server wait times
SERVER_STARTUP_WAIT = 3  # seconds to wait for server to start
SERVER_SHUTDOWN_WAIT = 2  # seconds to wait for server to shutdown

# Target users for brute force
DEFAULT_BRUTE_FORCE_TARGETS = ["user01", "user02", "user03"]

# Max attempts for testing
DEFAULT_MAX_ATTEMPTS = 50

# File paths (relative to simulator directory)
SERVER_CONFIG_PATH = "src/server/server_config.json"
SERVER_PATH = "src/server/server.py"
SETUP_DB_PATH = "src/server/setup_db.py"
FILE_USERS_DATA_PATH = "src/data/users.json"
# File names
FILE_SERVER_SCRIPT = "server.py"
FILE_SETUP_DB_SCRIPT = "setup_db.py"
FILE_USERS_DATA = "users.json"
FILE_SERVER_CONFIG = "server_config.json"

# Config keys
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
