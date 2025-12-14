"""
server.py
FastAPI server for user registration and login with SQLite database.
"""

import sqlite3

import server_const as const
import uvicorn
from database import get_user, init_database, insert_user
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
            "status": const.SERVER_SUCCESS,
            "message": const.SERVER_MSG_REGISTER_OK,
        }
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.post("/login")
async def login_user(request: LoginRequest):
    try:
        user = get_user(request.username)
        if user is None:
            return {
                "status": const.SERVER_FAILURE,
                "message": const.SERVER_MSG_LOGIN_INVALID,
            }

        # Unpack user data
        username, password_hash, salt, totp_secret = user

        # TODO: verify with hash_password()
        if request.password == password_hash:
            return {
                "status": const.SERVER_SUCCESS,
                "message": const.SERVER_MSG_LOGIN_OK,
            }
        else:
            return {
                "status": const.SERVER_FAILURE,
                "message": const.SERVER_MSG_LOGIN_INVALID,
            }
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.post("/login_totp")
async def login_totp_user(request: LoginTOTPRequest):
    # TODO: Implement later
    return {"status": const.SERVER_FAILURE, "message": "TOTP not implemented yet"}


if __name__ == "__main__":

    init_database()

    uvicorn.run(app, host=const.DEFAULT_HOST, port=const.DEFAULT_PORT)
