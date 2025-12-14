"""
server_const.py
Constants for authentication server configuration and responses.
"""

# Response statues
SERVER_SUCCESS = "success"
SERVER_FAILURE = "fail"

# Response messages
SERVER_MSG_REGISTER_OK = "User registered successfully"
SERVER_MSG_REGISTER_UNIQUE_FAIL = "Username already exist"
SERVER_MSG_LOGIN_OK = "User login successfully"
SERVER_MSG_LOGIN_INVALID = "Invalid credentials"

# Hash modes
HASH_SHA256 = "sha256"
HASH_BCRYPT = "bcrypt"
HASH_ARGON2ID = "argon2id"

# Defaults
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000
DEFAULT_HASH_MODE = HASH_SHA256

# Paths
DB_PATH = "src/server/db/auth.db"
CONFIG_PATH = "src/server/config/server_config.json"
USERS_JSON_PATH = "src/data/users.json"
LOG_DIR = "src/logs/attempts"
