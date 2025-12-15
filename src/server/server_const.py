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

# server config JSON keys
CONFIG_KEY_HOST = "host"
CONFIG_KEY_PORT = "port"
CONFIG_KEY_HASH_MODE = "hash_mode"
CONFIG_KEY_DEFENSES = "defenses"
CONFIG_KEY_PEPPER = "pepper"
CONFIG_KEY_PEPPER_VALUE = "pepper_value"

# Paths
DB_PATH = "src/server/db/auth.db"
CONFIG_PATH = "src/server/config/server_config.json"
USERS_JSON_PATH = "src/data/users.json"
LOG_DIR = "src/logs/attempts"
