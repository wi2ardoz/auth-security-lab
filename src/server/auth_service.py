"""
auth_service.py
Authentication service that orchestrates defense mechanisms and user verification.
"""

import time
from typing import Dict, Optional, Tuple

import server_const as const
from database import get_db_cursor, get_user
from defenses import (check_rate_limit, generate_captcha_token,
                      increment_failed_attempts, is_account_locked,
                      reset_failed_attempts, should_require_captcha,
                      validate_captcha_token, validate_totp_code,
                      verify_password)
from utils import get_hash_settings, log_attempt, utils_const


class DefenseResult:
    """Result of a defense check."""

    def __init__(self, passed: bool, response: Optional[Dict] = None):
        self.passed = passed
        self.response = response
        
class AuthService:
    """
    Service class that handles authentication logic and defense orchestration.
    """

    def __init__(self, config: Dict, log_filepath: str):
        """
        Initialize authentication service.

        Args:
            config: Server configuration dictionary
            log_filepath: Path to authentication log file
        """
        self.config = config
        self.log_filepath = log_filepath
        
    def authenticate(self, username: str, password: str,
                    captcha_token: Optional[str] = None) -> Dict:
        """
        Main authentication flow for username/password login.

        Orchestrates all defense mechanisms in order:
        1. Account Lockout
        2. Rate Limiting
        3. CAPTCHA
        4. Password Verification
        5. TOTP Check

        Args:
            username: Username to authenticate
            password: Password to verify
            captcha_token: Optional CAPTCHA token

        Returns:
            Response dictionary with status and message
        """
        start_time = time.time()
        defenses = self.config.get(utils_const.SCHEME_KEY_DEFENSES, {})

        with get_db_cursor() as cursor:
            # Defense 1: Account Lockout
            result = self._check_account_lockout(cursor, username, start_time)
            if not result.passed:
                return result.response

            # Defense 2: Rate Limiting
            result = self._check_rate_limit(username, start_time)
            if not result.passed:
                return result.response

            # Defense 3: CAPTCHA
            result = self._check_captcha(cursor, username, captcha_token, start_time)
            if not result.passed:
                return result.response

            # Verify user and password
            verified, totp_secret, error_response = self._verify_user_and_password(
                cursor, username, password, start_time
            )
            if not verified:
                return error_response

            # Password correct - reset failed attempts counter
            # This happens before TOTP check because password verification succeeded
            if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False) or \
               defenses.get(utils_const.SCHEME_KEY_DEFENSE_CAPTCHA, False):
                reset_failed_attempts(cursor, username)

            # Defense 4: TOTP (Two-Factor Authentication)
            # Password verified successfully, but second factor still required
            if defenses.get(utils_const.SCHEME_KEY_DEFENSE_TOTP, False) and totp_secret:
                self._log_attempt(
                    username,
                    start_time,
                    const.LOG_RESULT_SUCCESS,
                    totp_required=True,
                )
                return {
                    "status": const.SERVER_SUCCESS,
                    "message": const.SERVER_MSG_TOTP_REQUIRED,
                    "totp_required": True,
                }

            # Complete success (no TOTP required)
            self._log_attempt(username, start_time, const.LOG_RESULT_SUCCESS)
            return {
                "status": const.SERVER_SUCCESS,
                "message": const.SERVER_MSG_LOGIN_OK,
            }

    def authenticate_totp(self, username: str, totp_code: str) -> Dict:
        """
        TOTP authentication flow (second factor after password verification).

        Args:
            username: Username to authenticate
            totp_code: TOTP code to verify

        Returns:
            Response dictionary with status and message
        """
        start_time = time.time()
        defenses = self.config.get(utils_const.SCHEME_KEY_DEFENSES, {})

        # Verify user exists and has TOTP secret
        user = get_user(username)
        if user is None:
            self._log_attempt(
                username,
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
            self._log_attempt(
                username,
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
            totp_valid = validate_totp_code(totp_secret, totp_code)
            if totp_valid:
                # TOTP correct - reset failed attempts counter
                if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False) or \
                   defenses.get(utils_const.SCHEME_KEY_DEFENSE_CAPTCHA, False):
                    reset_failed_attempts(cursor, username)

                self._log_attempt(username, start_time, const.LOG_RESULT_SUCCESS)
                return {
                    "status": const.SERVER_SUCCESS,
                    "message": const.SERVER_MSG_LOGIN_OK,
                }
            else:
                self._log_attempt(
                    username,
                    start_time,
                    const.LOG_RESULT_FAILURE,
                    failure_reason=const.FAILURE_REASON_TOTP_INVALID,
                )
                return {
                    "status": const.SERVER_FAILURE,
                    "message": const.SERVER_MSG_TOTP_INVALID,
                }

    def _check_account_lockout(self, cursor, username: str, start_time: float) -> DefenseResult:
        """
        Defense 1: Account Lockout

        Check if account is locked due to too many failed attempts.

        Args:
            cursor: Database cursor
            username: Username to check
            start_time: Request start time

        Returns:
            DefenseResult with passed=False if account is locked
        """
        defenses = self.config.get(utils_const.SCHEME_KEY_DEFENSES, {})
        if not defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False):
            return DefenseResult(passed=True)

        locked, remaining = is_account_locked(cursor, username)
        if locked:
            self._log_attempt(
                username,
                start_time,
                const.LOG_RESULT_FAILURE,
                failure_reason=const.FAILURE_REASON_ACCOUNT_LOCKED,
            )
            return DefenseResult(
                passed=False,
                response={
                    "status": const.SERVER_FAILURE,
                    "message": const.SERVER_MSG_ACCOUNT_LOCKED,
                    "locked_until_seconds": remaining,
                }
            )
        return DefenseResult(passed=True)

    def _check_rate_limit(self, username: str, start_time: float) -> DefenseResult:
        """
        Defense 2: Rate Limiting

        Check if user is making requests too quickly.

        Args:
            username: Username to check
            start_time: Request start time

        Returns:
            DefenseResult with passed=False if rate limit exceeded
        """
        defenses = self.config.get(utils_const.SCHEME_KEY_DEFENSES, {})
        if not defenses.get(utils_const.SCHEME_KEY_DEFENSE_RATE_LIMIT, False):
            return DefenseResult(passed=True)

        allowed, retry_after = check_rate_limit(username)
        if not allowed:
            self._log_attempt(
                username,
                start_time,
                const.LOG_RESULT_FAILURE,
                failure_reason=const.FAILURE_REASON_RATE_LIMITED,
                retry_after=retry_after,
            )
            return DefenseResult(
                passed=False,
                response={
                    "status": const.SERVER_FAILURE,
                    "message": const.SERVER_MSG_RATE_LIMITED,
                    "retry_after": retry_after,
                }
            )
        return DefenseResult(passed=True)

    def _check_captcha(self, cursor, username: str, captcha_token: Optional[str],
                       start_time: float) -> DefenseResult:
        """
        Defense 3: CAPTCHA

        Check if CAPTCHA is required and validate token if provided.

        Args:
            cursor: Database cursor
            username: Username to check
            captcha_token: CAPTCHA token provided by user (optional)
            start_time: Request start time

        Returns:
            DefenseResult with passed=False if CAPTCHA required or invalid
        """
        defenses = self.config.get(utils_const.SCHEME_KEY_DEFENSES, {})
        if not defenses.get(utils_const.SCHEME_KEY_DEFENSE_CAPTCHA, False):
            return DefenseResult(passed=True)

        requires_captcha = should_require_captcha(cursor, username)
        if requires_captcha:
            if not captcha_token:
                # CAPTCHA required but not provided - generate and return token
                token = generate_captcha_token(username)
                self._log_attempt(
                    username,
                    start_time,
                    const.LOG_RESULT_FAILURE,
                    failure_reason=const.FAILURE_REASON_CAPTCHA_REQUIRED,
                )
                return DefenseResult(
                    passed=False,
                    response={
                        "status": const.SERVER_FAILURE,
                        "message": const.SERVER_MSG_CAPTCHA_REQUIRED,
                        "captcha_required": True,
                        "captcha_token": token,
                    }
                )
            else:
                # CAPTCHA provided - validate it
                if not validate_captcha_token(username, captcha_token):
                    self._log_attempt(
                        username,
                        start_time,
                        const.LOG_RESULT_FAILURE,
                        failure_reason=const.FAILURE_REASON_CAPTCHA_INVALID,
                    )
                    return DefenseResult(
                        passed=False,
                        response={
                            "status": const.SERVER_FAILURE,
                            "message": const.SERVER_MSG_CAPTCHA_INVALID,
                        }
                    )
        return DefenseResult(passed=True)

    def _verify_user_and_password(self, cursor, username: str, password: str,
                                   start_time: float) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Verify user exists and password is correct.

        Args:
            cursor: Database cursor
            username: Username to verify
            password: Password to verify
            start_time: Request start time

        Returns:
            Tuple of (success, totp_secret, error_response)
            - success: True if user exists and password correct
            - totp_secret: User's TOTP secret if they have one
            - error_response: Error response dict if verification failed
        """
        defenses = self.config.get(utils_const.SCHEME_KEY_DEFENSES, {})

        # Verify user exists
        user = get_user(username)
        if user is None:
            self._log_attempt(
                username,
                start_time,
                const.LOG_RESULT_FAILURE,
                failure_reason=const.FAILURE_REASON_INVALID_CREDENTIALS,
            )
            return False, None, {
                "status": const.SERVER_FAILURE,
                "message": const.SERVER_MSG_LOGIN_INVALID,
            }

        _, password_hash, salt, totp_secret = user

        # Verify password
        hash_mode, pepper = get_hash_settings(self.config)
        verified = verify_password(password, password_hash, hash_mode, salt=salt, pepper=pepper)

        if not verified:
            # Password incorrect - increment failed attempts counter
            if defenses.get(utils_const.SCHEME_KEY_DEFENSE_LOCKOUT, False) or \
               defenses.get(utils_const.SCHEME_KEY_DEFENSE_CAPTCHA, False):
                increment_failed_attempts(cursor, username)

            self._log_attempt(
                username,
                start_time,
                const.LOG_RESULT_FAILURE,
                failure_reason=const.FAILURE_REASON_INVALID_CREDENTIALS,
            )
            return False, None, {
                "status": const.SERVER_FAILURE,
                "message": const.SERVER_MSG_LOGIN_INVALID,
            }

        return True, totp_secret, None
    
    def _log_attempt(self, username: str, start_time: float, result: str,
                     failure_reason: Optional[str] = None,
                     retry_after: Optional[int] = None,
                     totp_required: bool = False):
        """
        Helper to log authentication attempt with automatic latency calculation.

        Args:
            username: Username attempted
            start_time: Request start time from time.time()
            result: const.LOG_RESULT_SUCCESS or const.LOG_RESULT_FAILURE
            failure_reason: Optional reason for failure
            retry_after: Optional seconds until retry allowed (for rate limiting)
            totp_required: Whether TOTP second factor is required (for success with pending TOTP)
        """
        latency_ms = (time.time() - start_time) * 1000
        log_attempt(
            self.log_filepath,
            username,
            result,
            latency_ms,
            self.config,
            failure_reason=failure_reason,
            retry_after=retry_after,
            totp_required=totp_required,
        )
