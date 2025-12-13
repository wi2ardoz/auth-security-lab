"""
server.py
Authentication Server - FastAPI + SQLite
"""

import os
import sqlite3

import server_const as const
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginTOTPRequest(BaseModel):
    username: str
    password: str
    totp_code: str


app = FastAPI()


@app.post("/register")
async def register_user(request: RegisterRequest):
    try:
        username = request.username
        password = request.password

        # TODO: Hash password
        # TODO: totp
        success = insert_user(username, password, None, None)
        if not success:
            return {
                "status": const.SERVER_FAILURE,
                "message": const.SERVER_MSG_REGISTER_UNIQUE_FAIL,
            }
        return {
            "status": const.SERVER_MSG_REGISTER_OK,
            "message": const.SERVER_MSG_REGISTER_OK,
        }
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.post("/login")
async def login_user(request: LoginRequest):
    username = request.username
    password = request.password
    # TODO
    return {"status": const.SERVER_SUCCESS, "message": const.SERVER_MSG_LOGIN_OK}


@app.post("/login_totp")
async def login_totp_user(request: LoginTOTPRequest):
    username = request.username
    password = request.password
    totp_code = request.totp_code
    # TODO
    return {"status": const.SERVER_SUCCESS, "message": const.SERVER_MSG_LOGIN_TOTP_OK}


def init_database():
    """
    Initialize SQLite database and create users table if it doesn't exist.
    """
    os.makedirs(os.path.dirname(const.DB_PATH), exist_ok=True)

    conn = sqlite3.connect(const.DB_PATH)
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
    print(f"Database initialized at {const.DB_PATH}")


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
        print(f"Username {username} was add to database at {const.DB_PATH}")
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False
    finally:
        conn.close()


if __name__ == "__main__":

    init_database()

    uvicorn.run(app, host=const.DEFAULT_HOST, port=const.DEFAULT_PORT)
