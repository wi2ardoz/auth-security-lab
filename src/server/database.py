"""
database.py
SQLite database management for user authentication.
"""

import os
import sqlite3

import server_const as server_const


def init_database():
    """
    Initialize SQLite database and create users table if it doesn't exist.
    """
    os.makedirs(os.path.dirname(server_const.DB_PATH), exist_ok=True)

    conn = sqlite3.connect(server_const.DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT,
                totp_secret TEXT
            )
        """
    )

    conn.commit()
    conn.close()


def insert_user(username, password_hash, salt=None, totp_secret=None):
    """
    Insert a new user into the database.

    :param username: Username (unique)
    :param password_hash: Hashed password
    :param salt: Salt value (for SHA256 mode only)
    :param totp_secret: TOTP (optional)
    :return: True if success, False if user already exists
    """
    try:
        conn = sqlite3.connect(server_const.DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, totp_secret) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, totp_secret),
        )

        conn.commit()
        print(f"Username {username} was added to database at {server_const.DB_PATH}")
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False
    finally:
        conn.close()


def get_user(username):
    """
    Retrieve user from database by username.

    :param username: Username to search for
    :return: Tuple (username, password_hash, salt, totp_secret)
        or None if not found
    """
    try:
        conn = sqlite3.connect(server_const.DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
                SELECT username, password_hash, salt, totp_secret
                FROM users
                WHERE username = ?
            """,
            (username,),
        )

        user = cursor.fetchone()
        conn.close()
        return user
    finally:
        conn.close()
