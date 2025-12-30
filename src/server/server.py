"""
server.py
FastAPI server for user registration and login with SQLite database.
"""

import sqlite3
import time

import server_const as const
import uvicorn
from database import get_db_cursor, get_user, init_database, insert_user
from defenses import (check_rate_limit, hash_password,
                      increment_failed_attempts, is_account_locked,
                      reset_failed_attempts, verify_password)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from utils import (get_hash_settings, get_next_log_filename, init_from_cli,
                   init_log_file, log_attempt, parse_cli_args, utils_const)


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
        start_time = time.time()
        defenses = app.state.config.get(utils_const.SCHEME_KEY_DEFENSES, {})

        # Defense 1 - Rate Limiting
        if defenses.get(utils_const.SCHEME_KEY_DEFENSE_RATE_LIMIT, False):
            allowed, retry_after = check_rate_limit(request.username)
            if not allowed:
                _log_attempt(
                    request.username,
                    start_time,
                    const.LOG_RESULT_FAILURE,
                    failure_reason=const.FAILURE_REASON_RATE_LIMITED,
                    retry_after=retry_after,
                )
                return {
                    "status": const.SERVER_FAILURE,
                    "message": const.SERVER_MSG_RATE_LIMITED,
                    "retry_after": retry_after,
                }

        # Use database cursor for lockout checks and user verification
        with get_db_cursor() as cursor:
            # Defense 2 - Account Lockout
            if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False):
                locked, remaining = is_account_locked(cursor, request.username)
                if locked:
                    _log_attempt(
                        request.username,
                        start_time,
                        const.LOG_RESULT_FAILURE,
                        failure_reason=const.FAILURE_REASON_ACCOUNT_LOCKED,
                    )
                    return {
                        "status": const.SERVER_FAILURE,
                        "message": const.SERVER_MSG_ACCOUNT_LOCKED,
                        "locked_until_seconds": remaining,
                    }

            # Verify user exists
            # WARNING - NOT FOR PRODUCTION USE
            # Attacker can do username enumeration attacks based on timing and messages
            user = get_user(request.username)
            if user is None:
                _log_attempt(
                    request.username,
                    start_time,
                    const.LOG_RESULT_FAILURE,
                    failure_reason=const.FAILURE_REASON_INVALID_CREDENTIALS,
                )
                return {
                    "status": const.SERVER_FAILURE,
                    "message": const.SERVER_MSG_LOGIN_INVALID,
                }
            username, password_hash, salt, totp_secret = user

            # Verify password
            hash_mode, pepper = get_hash_settings(app.state.config)
            verified = verify_password(
                request.password, password_hash, hash_mode, salt=salt, pepper=pepper
            )

            if verified:
                # Success - reset lockout counter
                if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False):
                    reset_failed_attempts(cursor, request.username)

                _log_attempt(request.username, start_time, const.LOG_RESULT_SUCCESS)
                return {
                    "status": const.SERVER_SUCCESS,
                    "message": const.SERVER_MSG_LOGIN_OK,
                }
            else:
                # Failure - increment lockout counter
                if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False):
                    increment_failed_attempts(cursor, request.username)

                _log_attempt(
                    request.username,
                    start_time,
                    const.LOG_RESULT_FAILURE,
                    failure_reason=const.FAILURE_REASON_INVALID_CREDENTIALS,
                )
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


def _log_attempt(username, start_time, result, failure_reason=None, retry_after=None):
    """
    Helper function to log authentication attempt with automatic latency calculation.

    :param username: Username attempted
    :param start_time: Request start time from time.time()
    :param result: const.LOG_RESULT_SUCCESS or const.LOG_RESULT_FAILURE
    :param failure_reason: Optional reason for failure (rate_limited, invalid_credentials, etc.)
    :param retry_after: Optional seconds until retry allowed (for rate limiting)
    """
    latency_ms = (time.time() - start_time) * 1000
    log_attempt(
        app.state.log_filepath,
        username,
        result,
        latency_ms,
        app.state.config,
        failure_reason=failure_reason,
        retry_after=retry_after,
    )


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

    # Start server
    host = app.state.config[utils_const.SCHEME_KEY_HOST]
    port = app.state.config[utils_const.SCHEME_KEY_PORT]
    print(f"✓ Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
