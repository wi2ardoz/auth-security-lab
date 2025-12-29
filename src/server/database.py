"""
database.py
SQLite database management for user authentication.
"""

import os
import sqlite3

import server_const as const


def init_database():
    """
    Initialize SQLite database and create users and auth_state tables 
    if they don't exist.
    """
    os.makedirs(os.path.dirname(const.DB_PATH), exist_ok=True)

    conn = sqlite3.connect(const.DB_PATH)
    cursor = conn.cursor()

    # Create users table
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

    # Create auth_state table
    cursor.execute(
        """
            CREATE TABLE IF NOT EXISTS auth_state (
                username TEXT PRIMARY KEY,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP NULL,
                last_request_time TIMESTAMP NULL,
                FOREIGN KEY (username) REFERENCES users(username)
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
        conn = sqlite3.connect(const.DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, totp_secret) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, totp_secret),
        )

        conn.commit()
        print(f"Username {username} was added to database at {const.DB_PATH}")
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
        conn = sqlite3.connect(const.DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
                SELECT username, password_hash, salt, totp_secret
                FROM users
                WHERE username = ?
            """,
            (username,),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def clear_users_table():
    """
    Remove all records from the users table.
    Useful for reseeding the database with new hashes.
    """
    try:
        conn = sqlite3.connect(const.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users")
        conn.commit()
    finally:
        conn.close()


def clear_auth_state_table():
    """
    Remove all records from the auth_state table.
    Critical for experiment isolation - ensures each experiment starts with clean state.
    """
    try:
        conn = sqlite3.connect(const.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM auth_state")
        conn.commit()
    finally:
        conn.close()
