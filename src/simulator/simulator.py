"""
simulator.py
Simulator for testing authentication server with different defense mechanisms.
Runs attack scenarios against configured server setups.
"""

import json
import random
import sys
import time
import subprocess
from typing import Dict, List
import argparse
import simulator_const as const
from attacks import password_spraying, brute_force_attack
import os
from pathlib import Path



class SimulatorRunner:
    """
    Runs attack simulations against the server with different configurations.
    """
    
    def __init__(self, config_path: str = None):
        """
        Initialize the simulator.
        
        :param config_path: Path to server configuration file
        """
        if config_path is None:
            config_path = const.SERVER_CONFIG_PATH
        
        self.config_path = config_path
        self.server_process = None
        self.original_config = None
        self._users_data = self._load_users_data() 
        self.root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) # Parent dir of src

    def _load_users_data(self) -> Dict:
        """
        Load users data from users.json file (cached).
        
        :return: Users data dictionary
        """

        users_file = const.FILE_USERS_DATA_PATH
            
        with open(users_file, 'r') as f:
            return json.load(f)
        
    def start_server(self, scenario_config: Dict = None):
        """
        Start the authentication server in a subprocess with flags based on scenario config.
        
        :param scenario_config: Scenario configuration dictionary with hash_mode and defenses
        """
        
        print("[*] Starting server...")
        
        # Build command-line arguments
        cmd = [sys.executable, const.SERVER_PATH]
        
        if scenario_config:
            # Add hash mode
            if const.CONFIG_KEY_HASH_MODE in scenario_config and scenario_config[const.CONFIG_KEY_HASH_MODE]:
                cmd.extend(["--hash", scenario_config[const.CONFIG_KEY_HASH_MODE]])
            
            # Add defense flags
            if const.CONFIG_KEY_DEFENSES in scenario_config:
                defenses = scenario_config[const.CONFIG_KEY_DEFENSES]
                
                if defenses.get(const.CONFIG_KEY_RATE_LIMIT):
                    cmd.append("--rate-limit")
                
                if defenses.get(const.CONFIG_KEY_LOCKOUT):
                    cmd.append("--lockout")
                
                if defenses.get(const.CONFIG_KEY_CAPTCHA):
                    cmd.append("--captcha")
                
                if defenses.get(const.CONFIG_KEY_TOTP):
                    cmd.append("--totp")
                
                if defenses.get(const.CONFIG_KEY_PEPPER):
                    cmd.append("--pepper")
        
        # Set working directory to server folder
        
        # Start server as subprocess
        self.server_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.root_dir
        )
        
        # Wait for server to start
        time.sleep(const.SERVER_STARTUP_WAIT)
        
        # Check if server is still running
        if self.server_process.poll() is not None:
            stdout, stderr = self.server_process.communicate()
            print("[!] Server failed to start!")
            print(f"    stdout: {stdout.decode()}")
            print(f"    stderr: {stderr.decode()}")
            return False
        
        print(f"[+] Server started (PID: {self.server_process.pid})")
        return True
    
    def stop_server(self):
        """Stop the authentication server."""
        if self.server_process:
            print("[*] Stopping server...")
            self.server_process.terminate()
            
            try:
                self.server_process.wait(timeout=const.SERVER_SHUTDOWN_WAIT)
            except subprocess.TimeoutExpired:
                print("[!] Server didn't stop gracefully, killing...")
                self.server_process.kill()
                self.server_process.wait()
            
            print("[+] Server stopped")
            self.server_process = None
    
    def reset_database(self):
        """
        Reset the database by running setup_db.py to repopulate with initial users.
        """
        
        print("[*] Resetting database...")

        result = subprocess.run(
            [sys.executable, const.SETUP_DB_PATH],
            capture_output=True,
            text=True,
            cwd=self.root_dir
        )
        
        if result.returncode == 0:
            print("[+] Database reset successfully")
        else:
            print("[!] Database reset failed!")
            print(f"    {result.stderr}")
    
    def get_usernames_from_data(self) -> List[str]:
        """
        Load usernames from users.json data file.
        
        :return: List of usernames
        """
        data = self._load_users_data()
        return [user[const.JSON_KEY_USERNAME] for user in data[const.JSON_KEY_USERS]]
    
    def get_brute_force_targets_by_category(self) -> List[str]:
        """
        Get one username from each category in users.json for brute force testing.
        
        :return: List of usernames (one per category)
        """
        
        # Group users by category
        categories = {}
        for user in self._users_data[const.JSON_KEY_USERS]:
            category = user.get('category', 'unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(user[const.JSON_KEY_USERNAME])
        
        # Select random username from each category
        targets = []
        for category in sorted(categories.keys()):
            if categories[category]:
                selected_user = random.choice(categories[category])
                targets.append(selected_user)
                print(f"[*] Selected '{selected_user}' from category '{category}'")
        
        return targets
    
    def run_password_spraying_attack(self, server_url: str, usernames: List[str]):
        """
        Run password spraying attack.
        
        :param server_url: Server URL
        :param usernames: List of usernames to target
        """
        print("\nRUNNING ATTACK: Password Spraying")
        
        password_spraying(server_url, usernames)
    
    def run_brute_force_attack(self, server_url: str, target_username: str, endpoint):
        """
        Run brute force attack against a specific user.
        
        :param server_url: Server URL
        :param target_username: Username to target
        :param max_attempts: Maximum attempts to make
        """
        print(f"\nRUNNING ATTACK: Brute Force (Target: {target_username})")
        
        brute_force_attack(server_url, target_username, endpoint=endpoint)
    
    def run_with_config(self, config: Dict, run_server):
        """
        Run attack with custom configuration.
        
        :param config: Configuration dictionary with hash_mode and defenses
        """
        # Display configuration
        print("\n# RUNNING SCENARIO WITH CONFIGURATION")
        print(f"# Hash: {config.get(const.CONFIG_KEY_HASH_MODE, 'None')}")
        enabled_defenses = [k for k, v in config[const.CONFIG_KEY_DEFENSES].items() if v]
        print(f"# Defenses: {', '.join(enabled_defenses) or 'None'}")
        
        # Start server with config
        if run_server:
            if not self.start_server(config):
                print("[!] Failed to start server, skipping attacks")
                return
        
            # Reset database
            self.reset_database()
        
        try:
            # Set server URL
            server_url = f"{const.SERVER_HOST}:{const.SERVER_PORT}"
            
            # Get all usernames
            usernames = self.get_usernames_from_data()
            
            # Run attacks based on type
            self.run_password_spraying_attack(server_url, usernames)
            
            # Run brute force on one user from each category
            brute_force_targets = self.get_brute_force_targets_by_category()
            print(brute_force_targets)
            for target_user in brute_force_targets:
                self.run_brute_force_attack(
                    server_url,
                    target_user,
                    endpoint=const.DEFAULT_ENDPOINT if config[const.CONFIG_KEY_DEFENSES].get(const.CONFIG_KEY_TOTP) == False
                    else const.TOTP_ENDPOINT
                )
        finally:
            if run_server:
                self.stop_server()
    
    def run_all_scenarios(self):
        """
        Run all defense scenarios in sequence.
        """
        scenarios = const.SCENARIOS
        
        print("\n* RUNNING ALL SCENARIOS")
        print(f"* Total scenarios: {len(scenarios)}")
        
        for scenario in scenarios:
            print(f"\n{'='*60}")
            print(f"SCENARIO: {scenario['name']}")
            print(f"{'='*60}")
            self.run_with_config(scenario["config"], attack_type="both")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Attack simulator for testing authentication server defenses"
    )
    
    # Hash mode argument
    parser.add_argument(
        "--hash",
        type=str,
        choices=[const.SHA256_HASHING, const.BCRYPT_HASHING, const.ARGON2ID_HASHING],
        default=None,
        help="Password hashing algorithm to use"
    )
    
    # Defense mechanism flags
    parser.add_argument(
        "--rate-limit",
        action="store_true",
        help="Enable rate limiting"
    )
    
    parser.add_argument(
        "--lockout",
        action="store_true",
        help="Enable account lockout"
    )
    
    parser.add_argument(
        "--captcha",
        action="store_true",
        help="Enable CAPTCHA"
    )
    
    parser.add_argument(
        "--totp",
        action="store_true",
        help="Enable TOTP"
    )
    
    parser.add_argument(
        "--pepper",
        action="store_true",
        help="Enable pepper"
    )
    
    # Run all scenarios flag
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all pre-defined scenarios (ignores other flags)"
    )
    
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Run attacks without server setup/teardown (for manual server control)"
    )
    args = parser.parse_args()
    return args

def main():
    """Main entry point for the simulator."""

    args = parse_args()

    
    simulator = SimulatorRunner()
    
    try:
        if args.all:
            # Run all pre-defined scenarios
            simulator.run_all_scenarios()
        else:
            # Build config from arguments
            config = {
                const.CONFIG_KEY_HASH_MODE: args.hash,
                const.CONFIG_KEY_DEFENSES: {
                    const.CONFIG_KEY_RATE_LIMIT: args.rate_limit,
                    const.CONFIG_KEY_LOCKOUT: args.lockout,
                    const.CONFIG_KEY_CAPTCHA: args.captcha,
                    const.CONFIG_KEY_TOTP: args.totp,
                    const.CONFIG_KEY_PEPPER: args.pepper
                }
            }
            
            # Run with custom config
            simulator.run_with_config(config, run_server=not args.manual)
    
    finally:
        pass
    
    print("\n[*] Simulation complete!")


if __name__ == "__main__":
    main()
