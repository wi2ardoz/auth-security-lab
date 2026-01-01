"""
server.py
FastAPI server for user registration and login with SQLite database.

Refactored to use AuthService for authentication logic separation.
"""

import sqlite3

import server_const as const
import uvicorn
from auth_service import AuthService
from database import init_database, insert_user
from defenses import hash_password
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from utils import (get_hash_settings, get_next_log_filename, init_from_cli,
                   init_log_file, parse_cli_args, utils_const)


# Request models
class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_token: str | None = None  # Optional CAPTCHA token


class LoginTOTPRequest(BaseModel):
    username: str
    totp_code: str


# FastAPI app
app = FastAPI()

# Authentication service (initialized in main)
auth_service: AuthService = None


@app.post("/register")
async def register_user(request: RegisterRequest):
    """
    Register a new user with username and password.

    Args:
        request: RegisterRequest with username and password

    Returns:
        Response with status and message
    """
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
    """
    Authenticate user with username and password.

    Orchestrates all defense mechanisms through AuthService:
    1. Account Lockout
    2. Rate Limiting
    3. CAPTCHA
    4. Password Verification
    5. TOTP Check

    Args:
        request: LoginRequest with username, password, and optional captcha_token

    Returns:
        Response with status and message
    """
    try:
        return auth_service.authenticate(
            request.username,
            request.password,
            request.captcha_token
        )
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


@app.post("/login_totp")
async def login_totp_user(request: LoginTOTPRequest):
    """
    Authenticate user with TOTP code (second factor).

    This endpoint is used after successful password authentication when
    TOTP is enabled for the user.

    Args:
        request: LoginTOTPRequest with username and totp_code

    Returns:
        Response with status and message
    """
    try:
        return auth_service.authenticate_totp(
            request.username,
            request.totp_code
        )
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


if __name__ == "__main__":

    # Initialize database
    init_database()

    # Parse command-line arguments
    args = parse_cli_args()

    # Load config with CLI overrides
    app.state.config = init_from_cli(const.CONFIG_PATH, args)

    # Initialize logging
    log_filepath = get_next_log_filename(app.state.config)
    init_log_file(log_filepath)
    app.state.log_filepath = log_filepath
    print(f"✓ Logging to: {log_filepath}")

    # Initialize authentication service
    auth_service = AuthService(app.state.config, log_filepath)

    # Start server
    host = app.state.config[utils_const.SCHEME_KEY_HOST]
    port = app.state.config[utils_const.SCHEME_KEY_PORT]
    print(f"✓ Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
