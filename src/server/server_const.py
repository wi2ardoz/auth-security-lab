"""
server_const.py
Constants for authentication server configuration and responses.
"""

# Response statues
SERVER_FAILURE = "fail"
SERVER_SUCCESS = "success"

# Response messages
SERVER_MSG_REGISTER_OK = "user registered successfully"
SERVER_MSG_LOGIN_OK = "user login successfully"
SERVER_MSG_LOGIN_TOTP_OK = "user login totp successfully"

# Hash modes
HASH_SHA256 = "sha256"
HASH_BCRYPT = "bcrypt"
HASH_ARGON2ID = "argon2id"

# Defaults
DEFAULT_PORT = 8000
DEFAULT_HASH_MODE = HASH_SHA256

# Paths
DB_PATH = "src/server/db/auth.db"
CONFIG_PATH = "src/server/config/server_config.json"
USERS_JSON_PATH = "src/data/users.json"
LOG_DIR = "src/logs/attempts"