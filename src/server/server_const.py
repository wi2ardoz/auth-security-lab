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

# Log result statuses
LOG_RESULT_SUCCESS = "success"
LOG_RESULT_FAILURE = "failure"

# Paths
DB_PATH = "src/server/db/auth.db"
CONFIG_PATH = "src/server/config/server_config.json"
USERS_JSON_PATH = "src/data/users.json"
LOG_DIR = "src/logs/attempts"
