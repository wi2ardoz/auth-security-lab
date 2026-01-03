"""
attacks_const.py
Constants for attack simulation methods.
"""
# Server Response codes
SERVER_SUCCESS = 200

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

# Attack configuration
DEFAULT_PASSWORD_LIMIT = 20000  # Maximum number of passwords to try in password spraying
DEFAULT_TIMEOUT = 10  # Default timeout for HTTP requests in seconds
ATTACK_TIMEOUT = 7200   # Maximum time for an attack in seconds (2 hours = 120 minutes)

