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
REL_PATH_PARENT = ".."
REL_PATH_SERVER_DIR = "server"
REL_PATH_DATA_DIR = "data"
REL_PATH_CONFIG_DIR = "config"

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

# Messages
MSG_BACKED_UP_CONFIG = "[*] Backed up original configuration"
MSG_RESTORED_CONFIG = "[*] Restored original configuration"
MSG_APPLIED_CONFIG = "[*] Applied configuration: {}"
MSG_STARTING_SERVER = "[*] Starting server..."
MSG_SERVER_STARTED = "[+] Server started (PID: {})"
MSG_SERVER_FAILED = "[!] Server failed to start!"
MSG_SERVER_FAILED_STDOUT = "    stdout: {}"
MSG_SERVER_FAILED_STDERR = "    stderr: {}"
MSG_STOPPING_SERVER = "[*] Stopping server..."
MSG_SERVER_STOPPED = "[+] Server stopped"
MSG_SERVER_KILL = "[!] Server didn't stop gracefully, killing..."
MSG_RESETTING_DB = "[*] Resetting database..."
MSG_DB_RESET_SUCCESS = "[+] Database reset successfully"
MSG_DB_RESET_FAILED = "[!] Database reset failed!"
MSG_UNKNOWN_SCENARIO = "[!] Unknown scenario: {}"
MSG_FAILED_START_SKIP = "[!] Failed to start server, skipping attacks"
MSG_SIMULATION_COMPLETE = "\n[*] Simulation complete!"

# Attack headers
ATTACK_HEADER_PASSWORD_SPRAY = "RUNNING ATTACK: Password Spraying"
ATTACK_HEADER_BRUTE_FORCE = "RUNNING ATTACK: Brute Force (Target: {})"

# Scenario headers
SCENARIO_HEADER_TEMPLATE = "# SCENARIO: {}"
SCENARIO_DESC_TEMPLATE = "# {}"

# Running all scenarios messages
MSG_RUNNING_ALL_SCENARIOS = "* RUNNING ALL SCENARIOS"
MSG_TOTAL_SCENARIOS = "* Total scenarios: {}"
