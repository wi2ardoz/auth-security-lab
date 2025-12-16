"""
server.py
FastAPI server for user registration and login with SQLite database.
"""

import sqlite3

import server_const as const
import uvicorn
from database import get_user, init_database, insert_user
from defenses import hash_password, verify_password
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from utils import get_hash_settings, init_from_cli, parse_cli_args, utils_const


# Request models
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


# FastAPI app
app = FastAPI()


@app.post("/register")
async def register_user(request: RegisterRequest):
    try:
        # Retrieve hash settings from config
        hash_mode, pepper = get_hash_settings(app.state.config)

        # Hash the password generate a salt as needed
        password_hash, salt = hash_password(
            request.password, hash_mode, salt=None, pepper=pepper
        )

        # TODO: Generate TOTP secret
        totp_secret = None

        success = insert_user(request.username, password_hash, salt, totp_secret)
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
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


@app.post("/login")
async def login_user(request: LoginRequest):
    try:
        user = get_user(request.username)
        if user is None:
            return {
                "status": const.SERVER_FAILURE,
                "message": const.SERVER_MSG_LOGIN_INVALID,
            }
        username, password_hash, salt, totp_secret = user

        # Retrieve hash settings from config
        hash_mode, pepper = get_hash_settings(app.state.config)

        verified = verify_password(
            request.password, password_hash, hash_mode, salt=salt, pepper=pepper
        )
        if verified:
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
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


@app.post("/login_totp")
async def login_totp_user(request: LoginTOTPRequest):
    # TODO: Implement later
    return {
        "status": const.SERVER_FAILURE,
        "message": "TOTP not implemented yet",
    }


if __name__ == "__main__":

    # Initialize database
    init_database()

    # Parse command-line arguments
    args = parse_cli_args()

    # Load config with CLI overrides
    app.state.config = init_from_cli(const.CONFIG_PATH, args)

    # Start server
    host = app.state.config[utils_const.SCHEME_KEY_HOST]
    port = app.state.config[utils_const.SCHEME_KEY_PORT]
    print(f"✓ Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
