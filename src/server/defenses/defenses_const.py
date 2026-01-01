"""
defenses_const.py
Constants for server defenses module.
"""

# Hash modes
HASH_SHA256 = "sha256"
HASH_BCRYPT = "bcrypt"
HASH_ARGON2ID = "argon2id"

# Salt size for SHA256 in bytes
SALT_SIZE_BYTES = 32

# Bcrypt cost factor (work factor: 2^12 iterations)
BCRYPT_ROUNDS = 12

# Rate limiting defaults
RATE_LIMIT_PER_SECOND = 2
RATE_LIMIT_PER_MINUTE = 10

# Account lockout defaults
LOCKOUT_THRESHOLD = 5       # Failed attempts before lockout
LOCKOUT_DURATION = 300      # Lockout duration in seconds (5 minutes)

# CAPTCHA defaults
CAPTCHA_THRESHOLD = 3       # Failed attempts before CAPTCHA required

# TOTP defaults
TOTP_VALID_WINDOW = 1       # ±30 seconds clock skew tolerance
