"""
utils_const.py
Configuration schema constants - JSON field names only.

IMPORTANT: This file defines FIELD NAMES (keys), NOT VALUES.

DON'T change these constants to configure the server.
DO edit server_config.json or use CLI flags to configure.

Example:
- SCHEME_KEY_HASH_MODE = "hash_mode"  ← This is the FIELD NAME
- To set hash mode to "bcrypt", edit server_config.json:
{"hash_mode": "bcrypt", ...} or use: --hash bcrypt

Only change these constants if you're modifying the config file schema itself
or the default values used in case of fallbacks.
"""

# Configuration file - Top level
SCHEME_KEY_HOST = "host"
SCHEME_VALUE_HOST_DEFAULT = "0.0.0.0"

SCHEME_KEY_PORT = "port"
SCHEME_VALUE_PORT_DEFAULT = 8000

SCHEME_KEY_HASH_MODE = "hash_mode"
SCHEME_VALUE_HASH_MODE_DEFAULT = "sha256"

SCHEME_KEY_DEFENSES = "defenses"

SCHEME_KEY_PEPPER_VALUE = "pepper_value"
SCHEME_VALUE_PEPPER_DEFAULT = "my_secret_pepper_value"

SCHEME_KEY_GROUP_SEED = "group_seed"
SCHEME_VALUE_GROUP_SEED_DEFAULT = "519933725"

# Configuration file - Defense mechanisms
SCHEME_KEY_DEFENSE_RATE_LIMIT = "rate_limit"
SCHEME_VALUE_DEFENSE_RATE_LIMIT_DEFAULT = False

SCHEME_KEY_DEFENSE_LOCKOUT = "lockout"
SCHEME_VALUE_DEFENSE_LOCKOUT_DEFAULT = False

SCHEME_KEY_DEFENSE_CAPTCHA = "captcha"
SCHEME_VALUE_DEFENSE_CAPTCHA_DEFAULT = False

SCHEME_KEY_DEFENSE_TOTP = "totp"
SCHEME_VALUE_DEFENSE_TOTP_DEFAULT = False

SCHEME_KEY_DEFENSE_PEPPER = "pepper"
SCHEME_VALUE_DEFENSE_PEPPER_DEFAULT = False

# All required config keys (for validation)
SCHEME_REQUIRED_KEYS = [
    SCHEME_KEY_HOST,
    SCHEME_KEY_PORT,
    SCHEME_KEY_HASH_MODE,
    SCHEME_KEY_DEFENSES,
    SCHEME_KEY_PEPPER_VALUE,
    SCHEME_KEY_GROUP_SEED,
]

# All defense keys
SCHEME_DEFENSE_KEYS = [
    SCHEME_KEY_DEFENSE_RATE_LIMIT,
    SCHEME_KEY_DEFENSE_LOCKOUT,
    SCHEME_KEY_DEFENSE_CAPTCHA,
    SCHEME_KEY_DEFENSE_TOTP,
    SCHEME_KEY_DEFENSE_PEPPER,
]
