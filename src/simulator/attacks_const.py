"""
attacks_const.py
Constants for attack simulation methods.
"""

# Default values
DEFAULT_LOCALHOST = "localhost"
DEFAULT_SERVER_BIND_ADDRESS = "0.0.0.0"
DEFAULT_TIMEOUT = 10  # seconds

# Password generation ranges
PASSWORD_GEN_NUMBER_START = 0
PASSWORD_GEN_NUMBER_END = 10000
PASSWORD_GEN_NUMBER_STEP = 1111

PASSWORD_GEN_YEAR_START = 1980
PASSWORD_GEN_YEAR_END = 2026

PASSWORD_GEN_COMMON_WORDS = ["admin", "user", "test", "password", "welcome"]
PASSWORD_GEN_NUMBER_RANGE = 10

# Password file paths
PASSWORDS_FILE_PATH = "src/data/passwords.json"

# Common passwords for quick testing
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "12345678",
    "qwerty", "abc123", "letmein", "welcome", "monkey"
]
