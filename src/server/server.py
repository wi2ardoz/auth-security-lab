"""
server.py
FastAPI server for user registration and login with SQLite database.
"""

import sqlite3
import time

import server_const as const
import uvicorn
from database import get_db_cursor, get_user, init_database, insert_user
from defenses import (check_rate_limit, generate_captcha_token, hash_password,
                      increment_failed_attempts, is_account_locked,
                      reset_failed_attempts, should_require_captcha,
                      validate_captcha_token, validate_totp_code,
                      verify_password)
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
    captcha_token: str | None = None  # Optional CAPTCHA token


class LoginTOTPRequest(BaseModel):
    username: str
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

            # Defense 3 - CAPTCHA
            if defenses.get(utils_const.SCHEME_KEY_DEFENSE_CAPTCHA, False):
                requires_captcha = should_require_captcha(cursor, request.username)
                if requires_captcha:
                    if not request.captcha_token:
                        # CAPTCHA required but not provided - generate and return token
                        captcha_token = generate_captcha_token(request.username)
                        _log_attempt(
                            request.username,
                            start_time,
                            const.LOG_RESULT_FAILURE,
                            failure_reason=const.FAILURE_REASON_CAPTCHA_REQUIRED,
                        )
                        return {
                            "status": const.SERVER_FAILURE,
                            "message": const.SERVER_MSG_CAPTCHA_REQUIRED,
                            "captcha_required": True,
                            "captcha_token": captcha_token,
                        }
                    else:
                        # CAPTCHA provided - validate it
                        if not validate_captcha_token(request.username, request.captcha_token):
                            _log_attempt(
                                request.username,
                                start_time,
                                const.LOG_RESULT_FAILURE,
                                failure_reason=const.FAILURE_REASON_CAPTCHA_INVALID,
                            )
                            return {
                                "status": const.SERVER_FAILURE,
                                "message": const.SERVER_MSG_CAPTCHA_INVALID,
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
                # Defense 4 - TOTP (Two-Factor Authentication)
                if defenses.get(utils_const.SCHEME_KEY_DEFENSE_TOTP, False) and totp_secret:
                    # User has TOTP enabled - require second factor
                    _log_attempt(
                        request.username,
                        start_time,
                        const.LOG_RESULT_FAILURE,
                        failure_reason=const.FAILURE_REASON_TOTP_REQUIRED,
                    )
                    return {
                        "status": const.SERVER_FAILURE,
                        "message": const.SERVER_MSG_TOTP_REQUIRED,
                        "totp_required": True,
                    }

                # Success - reset failed attempts counter (for lockout/CAPTCHA)
                if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False) or \
                   defenses.get(utils_const.SCHEME_KEY_DEFENSE_CAPTCHA, False):
                    reset_failed_attempts(cursor, request.username)

                _log_attempt(request.username, start_time, const.LOG_RESULT_SUCCESS)
                return {
                    "status": const.SERVER_SUCCESS,
                    "message": const.SERVER_MSG_LOGIN_OK,
                }
            else:
                # Failure - increment failed attempts counter (for lockout/CAPTCHA)
                if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False) or \
                   defenses.get(utils_const.SCHEME_KEY_DEFENSE_CAPTCHA, False):
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
    try:
        start_time = time.time()

        # Verify user exists and has TOTP secret
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
        _, _, _, totp_secret = user

        # Verify TOTP secret exists
        if not totp_secret:
            _log_attempt(
                request.username,
                start_time,
                const.LOG_RESULT_FAILURE,
                failure_reason=const.FAILURE_REASON_TOTP_INVALID,
            )
            return {
                "status": const.SERVER_FAILURE,
                "message": const.SERVER_MSG_TOTP_INVALID,
            }

        # Validate TOTP code
        with get_db_cursor() as cursor:
            totp_valid = validate_totp_code(totp_secret, request.totp_code)
            if totp_valid:
                # TOTP correct - reset failed attempts counter (for lockout/CAPTCHA)
                defenses = app.state.config.get(utils_const.SCHEME_KEY_DEFENSES, {})
                if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False) or \
                   defenses.get(utils_const.SCHEME_KEY_DEFENSE_CAPTCHA, False):
                    reset_failed_attempts(cursor, request.username)

                _log_attempt(request.username, start_time, const.LOG_RESULT_SUCCESS)
                return {
                    "status": const.SERVER_SUCCESS,
                    "message": const.SERVER_MSG_LOGIN_OK,
                }
            else:
                _log_attempt(
                    request.username,
                    start_time,
                    const.LOG_RESULT_FAILURE,
                    failure_reason=const.FAILURE_REASON_TOTP_INVALID,
                )
                return {
                    "status": const.SERVER_FAILURE,
                    "message": const.SERVER_MSG_TOTP_INVALID,
                }

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


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
