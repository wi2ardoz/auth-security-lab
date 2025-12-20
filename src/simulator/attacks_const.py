"""
attacks_const.py
Constants for attack simulation methods.
"""

# Attack types
ATTACK_TYPE_PASSWORD_SPRAYING = "password_spraying"
ATTACK_TYPE_BRUTE_FORCE = "brute_force"
ATTACK_TYPE_DICTIONARY = "dictionary"

# Log directory
LOG_DIR_ATTACKS = "attacks"

# Default values
DEFAULT_DELAY = 0.1
DEFAULT_TIMEOUT = 5
DEFAULT_LOCALHOST = "localhost"
DEFAULT_SERVER_BIND_ADDRESS = "0.0.0.0"

# Common passwords for password spraying attack
COMMON_PASSWORDS = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1qaz2wsx",
    "7777777",
    "121212",
    "000000",
]

# Password generation ranges
PASSWORD_GEN_NUMBER_START = 0
PASSWORD_GEN_NUMBER_END = 10000
PASSWORD_GEN_NUMBER_STEP = 1111

PASSWORD_GEN_YEAR_START = 1980
PASSWORD_GEN_YEAR_END = 2026

PASSWORD_GEN_COMMON_WORDS = ["admin", "user", "test", "password", "welcome"]
PASSWORD_GEN_NUMBER_RANGE = 10
