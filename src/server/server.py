"""
server.py
FastAPI server for user registration and login with SQLite database.
"""

import sqlite3

import server_const as server_const
import uvicorn
from database import get_user, init_database, insert_user
from defenses import hash_password, verify_password
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
        # TODO: Load from config
        hash_mode = server_const.DEFAULT_HASH_MODE
        pepper = None

        # Hash the password
        password_hash, salt = hash_password(
            request.password, hash_mode, salt=None, pepper=pepper
        )

        # TODO: Generate TOTP secret
        totp_secret = None

        success = insert_user(request.username, password_hash, salt, totp_secret)
        if not success:
            return {
                "status": server_const.SERVER_FAILURE,
                "message": server_const.SERVER_MSG_REGISTER_UNIQUE_FAIL,
            }
        return {
            "status": server_const.SERVER_SUCCESS,
            "message": server_const.SERVER_MSG_REGISTER_OK,
        }

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


@app.post("/login")
async def login_user(request: LoginRequest):
    try:
        user = get_user(request.username)
        if user is None:
            return {
                "status": server_const.SERVER_FAILURE,
                "message": server_const.SERVER_MSG_LOGIN_INVALID,
            }
        username, password_hash, salt, totp_secret = user

        # TODO: Load from config
        hash_mode = server_const.DEFAULT_HASH_MODE
        pepper = None

        verified = verify_password(
            request.password, password_hash, hash_mode, salt=salt, pepper=pepper
        )
        if verified:
            return {
                "status": server_const.SERVER_SUCCESS,
                "message": server_const.SERVER_MSG_LOGIN_OK,
            }
        else:
            return {
                "status": server_const.SERVER_FAILURE,
                "message": server_const.SERVER_MSG_LOGIN_INVALID,
            }

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


@app.post("/login_totp")
async def login_totp_user(request: LoginTOTPRequest):
    # TODO: Implement later
    return {
        "status": server_const.SERVER_FAILURE,
        "message": "TOTP not implemented yet",
    }


if __name__ == "__main__":

    init_database()

    uvicorn.run(app, host=server_const.DEFAULT_HOST, port=server_const.DEFAULT_PORT)
