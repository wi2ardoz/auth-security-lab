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
