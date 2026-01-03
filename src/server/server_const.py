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
SERVER_MSG_RATE_LIMITED = "Too many requests. Please try again later."
SERVER_MSG_ACCOUNT_LOCKED = "Account is locked. Please try again later."
SERVER_MSG_CAPTCHA_REQUIRED = "CAPTCHA required. Token provided in response."
SERVER_MSG_CAPTCHA_INVALID = "Invalid or expired CAPTCHA token."
SERVER_MSG_TOTP_REQUIRED = "Password correct, TOTP required."
SERVER_MSG_TOTP_INVALID = "Invalid TOTP code."

# Log result statuses
LOG_RESULT_SUCCESS = "success"
LOG_RESULT_FAILURE = "failure"

# Failure reasons (for logging)
FAILURE_REASON_INVALID_CREDENTIALS = "invalid_credentials"
FAILURE_REASON_RATE_LIMITED = "rate_limited"
FAILURE_REASON_ACCOUNT_LOCKED = "account_locked"
FAILURE_REASON_CAPTCHA_REQUIRED = "captcha_required"
FAILURE_REASON_CAPTCHA_INVALID = "captcha_invalid"
FAILURE_REASON_TOTP_INVALID = "totp_invalid"

# Paths
DB_PATH = "src/server/db/auth.db"
CONFIG_PATH = "src/server/config/server_config.json"
USERS_JSON_PATH = "src/data/users.json"
LOG_DIR = "src/logs/attempts"
