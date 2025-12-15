"""
hash.py
Password hashing and verification functions.
Supports SHA256+salt, bcrypt, and argon2id.
"""

import hashlib
import os

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from defenses import defenses_const


def hash_password(password, hash_mode, salt=None, pepper=None):
    """
    Hash a password using the specified hash mode.

    :param password: Plain text password
    :param hash_mode: Hash mode string ("sha256", "bcrypt", "argon2id")
    :param salt: Existing salt for verification, or None to generate new
    :param pepper: Pepper value (optional, for additional security)
    :return: Tuple (password_hash, salt)
        or (password_hash, None) for bcrypt/argon2id
    """
    if hash_mode == defenses_const.HASH_SHA256:
        if salt is None:
            salt = os.urandom(defenses_const.SALT_SIZE_BYTES).hex()

        combined = salt + password
        if pepper:
            combined += pepper

        # Hash the combination
        password_hash = hashlib.sha256(combined.encode()).hexdigest()

        return (password_hash, salt)

    elif hash_mode == defenses_const.HASH_BCRYPT:
        password_with_pepper = password + pepper if pepper else password

        # Bcrypt generates salt internally
        password_hash = bcrypt.hashpw(
            password_with_pepper.encode(),
            bcrypt.gensalt(rounds=defenses_const.BCRYPT_ROUNDS),
        ).decode()

        return (password_hash, None)

    elif hash_mode == defenses_const.HASH_ARGON2ID:
        password_with_pepper = password + pepper if pepper else password

        # Argon2 generates salt internally
        ph = PasswordHasher()
        password_hash = ph.hash(password_with_pepper)

        return (password_hash, None)

    else:
        raise ValueError(f"Invalid hash mode: {hash_mode}")


def verify_password(password, stored_hash, hash_mode, salt=None, pepper=None):
    """
    Verify a password against a stored hash.

    :param password: Plain text password to verify
    :param stored_hash: Stored password hash from database
    :param hash_mode: Hash mode used ("sha256", "bcrypt", "argon2id")
    :param salt: Stored salt from database (None for bcrypt/argon2id)
    :param pepper: Pepper value (optional)
    :return: True if password matches, False otherwise
    """
    if hash_mode == defenses_const.HASH_SHA256:
        try:
            new_hash, _ = hash_password(password, hash_mode, salt, pepper)
            return new_hash == stored_hash
        except Exception:
            return False

    elif hash_mode == defenses_const.HASH_BCRYPT:
        try:
            password_with_pepper = password + pepper if pepper else password
            return bcrypt.checkpw(password_with_pepper.encode(), stored_hash.encode())
        except (ValueError, Exception):
            return False

    elif hash_mode == defenses_const.HASH_ARGON2ID:
        try:
            ph = PasswordHasher()
            password_with_pepper = password + pepper if pepper else password
            ph.verify(stored_hash, password_with_pepper)
            return True
        except (VerifyMismatchError, InvalidHashError, Exception):
            return False

    else:
        raise ValueError(f"Invalid hash mode: {hash_mode}")
