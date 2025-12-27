"""
simulator.py
Simulator for testing authentication server with different defense mechanisms.
Runs attack scenarios against configured server setups.
"""

import json
import os
import random
import sys
import time
import subprocess
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import simulator_const as const
from attacks import password_spraying, brute_force_attack, get_server_url_from_config, load_server_config
from server.utils.config import load_config, save_config
from server.utils import utils_const
from server.defenses import defenses_const


class DefensePlaybook:
    """
    Defines different defense configurations to test against attacks.
    Each scenario represents a different security posture.
    """
    
    @staticmethod
    def get_scenario(scenario_name: str) -> Dict:
        """
        Get configuration for a specific defense scenario.
        
        :param scenario_name: Name of the scenario
        :return: Configuration dictionary
        """
        scenarios = {
            const.SCENARIO_NO_DEFENSES: {
                "name": const.SCENARIO_NAME_NO_DEFENSES,
                "description": const.SCENARIO_DESC_NO_DEFENSES,
                "config": {
                    const.CONFIG_KEY_HASH_MODE: None,
                    const.CONFIG_KEY_DEFENSES: {
                        const.CONFIG_KEY_RATE_LIMIT: False,
                        const.CONFIG_KEY_LOCKOUT: False,
                        const.CONFIG_KEY_CAPTCHA: False,
                        const.CONFIG_KEY_TOTP: False,
                        const.CONFIG_KEY_PEPPER: False
                    }
                }
            },
            const.SCENARIO_BASIC_HASHING: {
                "name": const.SCENARIO_NAME_BASIC_HASHING,
                "description": const.SCENARIO_DESC_BASIC_HASHING,
                "config": {
                    const.CONFIG_KEY_HASH_MODE: defenses_const.HASH_SHA256,
                    const.CONFIG_KEY_DEFENSES: {
                        const.CONFIG_KEY_RATE_LIMIT: False,
                        const.CONFIG_KEY_LOCKOUT: False,
                        const.CONFIG_KEY_CAPTCHA: False,
                        const.CONFIG_KEY_TOTP: False,
                        const.CONFIG_KEY_PEPPER: False
                    }
                }
            },
            const.SCENARIO_STRONG_HASHING: {
                "name": const.SCENARIO_NAME_STRONG_HASHING,
                "description": const.SCENARIO_DESC_STRONG_HASHING,
                "config": {
                    const.CONFIG_KEY_HASH_MODE: defenses_const.HASH_ARGON2ID,
                    const.CONFIG_KEY_DEFENSES: {
                        const.CONFIG_KEY_RATE_LIMIT: False,
                        const.CONFIG_KEY_LOCKOUT: False,
                        const.CONFIG_KEY_CAPTCHA: False,
                        const.CONFIG_KEY_TOTP: False,
                        const.CONFIG_KEY_PEPPER: False
                    }
                }
            },
            const.SCENARIO_RATE_LIMIT: {
                "name": const.SCENARIO_NAME_RATE_LIMIT,
                "description": const.SCENARIO_DESC_RATE_LIMIT,
                "config": {
                    const.CONFIG_KEY_HASH_MODE: defenses_const.HASH_SHA256,
                    const.CONFIG_KEY_DEFENSES: {
                        const.CONFIG_KEY_RATE_LIMIT: True,
                        const.CONFIG_KEY_LOCKOUT: False,
                        const.CONFIG_KEY_CAPTCHA: False,
                        const.CONFIG_KEY_TOTP: False,
                        const.CONFIG_KEY_PEPPER: False
                    }
                }
            },
            const.SCENARIO_LOCKOUT: {
                "name": const.SCENARIO_NAME_LOCKOUT,
                "description": const.SCENARIO_DESC_LOCKOUT,
                "config": {
                    const.CONFIG_KEY_HASH_MODE: defenses_const.HASH_SHA256,
                    const.CONFIG_KEY_DEFENSES: {
                        const.CONFIG_KEY_RATE_LIMIT: False,
                        const.CONFIG_KEY_LOCKOUT: True,
                        const.CONFIG_KEY_CAPTCHA: False,
                        const.CONFIG_KEY_TOTP: False,
                        const.CONFIG_KEY_PEPPER: False
                    }
                }
            },
            const.SCENARIO_FULL_DEFENSES: {
                "name": const.SCENARIO_NAME_FULL_DEFENSES,
                "description": const.SCENARIO_DESC_FULL_DEFENSES,
                "config": {
                    const.CONFIG_KEY_HASH_MODE: defenses_const.HASH_ARGON2ID,
                    const.CONFIG_KEY_DEFENSES: {
                        const.CONFIG_KEY_RATE_LIMIT: True,
                        const.CONFIG_KEY_LOCKOUT: True,
                        const.CONFIG_KEY_CAPTCHA: False,
                        const.CONFIG_KEY_TOTP: False,
                        const.CONFIG_KEY_PEPPER: True
                    }
                }
            }
        }
        
        return scenarios.get(scenario_name)


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
    
    def _load_users_data(self) -> Dict:
        """
        Load users data from users.json file (cached).
        
        :return: Users data dictionary
        """

        users_file = const.FILE_USERS_DATA_PATH
            
        with open(users_file, 'r') as f:
            return json.load(f)
        
    
    def backup_config(self):
        """Backup the current server configuration."""
        self.original_config = load_config(self.config_path)
        print("[*] Backed up original configuration")
    
    def restore_config(self):
        """Restore the original server configuration."""
        if self.original_config:
            save_config(self.config_path, self.original_config)
            print("[*] Restored original configuration")
    
    def apply_scenario_config(self, scenario: Dict):
        """
        Apply a defense scenario configuration to the server.
        
        :param scenario: Scenario dictionary with config
        """
        current_config = load_config(self.config_path)
        
        # Update with scenario config
        if scenario["config"][const.CONFIG_KEY_HASH_MODE] is not None:
            current_config[const.CONFIG_KEY_HASH_MODE] = scenario["config"][const.CONFIG_KEY_HASH_MODE]
        
        current_config[const.CONFIG_KEY_DEFENSES] = scenario["config"][const.CONFIG_KEY_DEFENSES]
        
        save_config(self.config_path, current_config)
        print(f"[*] Applied configuration: {scenario['name']}")
        print(f"    {scenario['description']}")
    
    def start_server(self):
        """
        Start the authentication server in a subprocess.
        """
        
        print("[*] Starting server...")
        
        # Start server as subprocess
        self.server_process = subprocess.Popen(
            [sys.executable, const.SERVER_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=const.SERVER_PATH
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
            [sys.executable, const.SETUP_DB_FILE],
            capture_output=True,
            text=True,
            cwd=const.SETUP_DB_PATH
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
        data = self.load_users_data()
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
    
    def run_brute_force_attack(self, server_url: str, target_username: str, max_attempts: int = None):
        """
        Run brute force attack against a specific user.
        
        :param server_url: Server URL
        :param target_username: Username to target
        :param max_attempts: Maximum attempts to make
        """
        print(f"\nRUNNING ATTACK: Brute Force (Target: {target_username})")
        
        brute_force_attack(server_url, target_username, max_attempts=max_attempts)
    
    def run_scenario(self, scenario_name: str, run_attacks: bool = True):
        """
        Run a complete test scenario with a specific defense configuration.
        
        :param scenario_name: Name of the defense scenario
        :param run_attacks: Whether to run attacks (True) or just setup (False)
        """
        scenario = DefensePlaybook.get_scenario(scenario_name)
        
        if not scenario:
            print(f"[!] Unknown scenario: {scenario_name}")
            return
        
        print(f"\n# SCENARIO: {scenario['name']}")
        print(f"# {scenario['description']}")
        
        # Apply configuration
        self.apply_scenario_config(scenario)
        
        # Reset database with new configuration
        self.reset_database()
        
        # Start server
        if not self.start_server():
            print("[!] Failed to start server, skipping attacks")
            return
        
        try:
            if run_attacks:
                # Get server URL
                config = load_server_config(self.config_path)
                server_url = get_server_url_from_config(config)
                
                # Get all usernames
                usernames = self.get_usernames_from_data()
                
                # Run password spraying attack
                self.run_password_spraying_attack(server_url, usernames)
                
                # Run brute force attacks on select users (one from each category)
                brute_force_targets = self.get_brute_force_targets_by_category()
                for target_user in brute_force_targets:
                    self.run_brute_force_attack(
                        server_url, 
                        target_user,
                        max_attempts=const.DEFAULT_MAX_ATTEMPTS
                    )
        
        finally:
            # Always stop the server
            self.stop_server()
    
    def run_all_scenarios(self):
        """
        Run all defense scenarios in sequence.
        """
        scenarios = [
            const.SCENARIO_NO_DEFENSES,
            const.SCENARIO_BASIC_HASHING,
            const.SCENARIO_STRONG_HASHING,
            const.SCENARIO_RATE_LIMIT,
            const.SCENARIO_LOCKOUT,
            const.SCENARIO_FULL_DEFENSES
        ]
        
        print("\n* RUNNING ALL SCENARIOS")
        print(f"* Total scenarios: {len(scenarios)}")
        
        for scenario_name in scenarios:
            self.run_scenario(scenario_name)


def main():
    """Main entry point for the simulator."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Attack simulator for testing authentication server defenses"
    )
    
    parser.add_argument(
        "--scenario",
        type=str,
        choices=[
            const.SCENARIO_NO_DEFENSES,
            const.SCENARIO_BASIC_HASHING,
            const.SCENARIO_STRONG_HASHING,
            const.SCENARIO_RATE_LIMIT,
            const.SCENARIO_LOCKOUT,
            const.SCENARIO_FULL_DEFENSES,
            const.SCENARIO_ALL
        ],
        default=const.SCENARIO_ALL,
        help="Defense scenario to test"
    )
    
    args = parser.parse_args()
    
    simulator = SimulatorRunner()
    
    try:
        
        if args.scenario == const.SCENARIO_ALL:
            simulator.run_all_scenarios()
        else:
            simulator.run_scenario(args.scenario)

    finally:
        # Restore original config unless disabled
        if not args.no_backup:
            simulator.restore_config()
    
    print("\n[*] Simulation complete!")


if __name__ == "__main__":
    main()
