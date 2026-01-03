"""
simulator.py
Simulator for testing authentication server with different defense mechanisms.
Runs attack scenarios against configured server setups.
"""

from glob import glob
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
        # Set UTF-8 encoding to handle Unicode output on Windows
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'

        self.server_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.root_dir,
            env=env
        )
        
        # Wait for server to start
        time.sleep(const.SERVER_STARTUP_WAIT)
        
        # Check if server is still running
        if self.server_process.poll() is not None:
            print("[!] Server failed to start!")
            print(f"    Exit code: {self.server_process.returncode}")
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

        # Set UTF-8 encoding to handle Unicode output on Windows
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'

        result = subprocess.run(
            [sys.executable, const.SETUP_DB_PATH],
            capture_output=True,
            text=True,
            cwd=self.root_dir,
            env=env,
            encoding='utf-8'
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
        Returns users ordered from weakest to strongest.

        :return: List of usernames (one per category, weakest to strongest)
        """

        # Define strength ordering (weakest to strongest)
        strength_order = ['weak', 'medium', 'strong']

        # Group users by category
        categories = {}
        for user in self._users_data[const.JSON_KEY_USERS]:
            category = user.get('category', 'unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(user[const.JSON_KEY_USERNAME])

        # Select random username from each category in strength order
        targets = []
        for category in strength_order:
            if category in categories and categories[category]:
                selected_user = random.choice(categories[category])
                targets.append(selected_user)
                print(f"[*] Selected '{selected_user}' from category '{category}'")

        # Add any unknown categories at the end
        for category in sorted(categories.keys()):
            if category not in strength_order and categories[category]:
                selected_user = random.choice(categories[category])
                targets.append(selected_user)
                print(f"[*] Selected '{selected_user}' from category '{category}'")

        return targets

    def rename_log_file(self, attack_type: str):
        """
        Rename the most recently modified log file by appending the attack type.

        :param attack_type: Type of attack to append to the filename
        :return: New file path or None if no log files found
        """
        # Define the logs directory path
        logs_directory = os.path.join(self.root_dir, const.LOGS_DIRECTORY_PATH)

        # Get all files in the logs directory
        files = [f for f in glob(os.path.join(logs_directory, '*'))
                 if os.path.isfile(f)]

        if not files:
            print("[!] No log files found in logs directory")
            return None

        # Find the most recently modified file
        most_recent = max(files, key=os.path.getmtime)

        # Extract the file name and extension
        dir_path = os.path.dirname(most_recent)
        file_name = os.path.basename(most_recent)
        name, ext = os.path.splitext(file_name)

        # Create new file name with attack type appended
        new_name = f"{name}_{attack_type}{ext}"
        new_path = os.path.join(dir_path, new_name)

        # Rename the file
        os.rename(most_recent, new_path)
        print(f"[+] Renamed log file: {file_name} -> {new_name}")

        return new_path

    def run_password_spraying_attack(self, server_url: str, usernames: List[str], start_time: float = None):
        """
        Run password spraying attack.

        :param server_url: Server URL
        :param usernames: List of usernames to target
        :param start_time: Optional scenario start time for timeout tracking
        :return: Elapsed time since start_time
        """
        print("\nRUNNING ATTACK: Password Spraying")

        return password_spraying(server_url, usernames, start_time=start_time)

    def run_brute_force_attack(self, server_url: str, target_username: str, endpoint, start_time: float = None):
        """
        Run brute force attack against a specific user.

        :param server_url: Server URL
        :param target_username: Username to target
        :param endpoint: Login endpoint to use
        :param start_time: Optional scenario start time for timeout tracking
        :return: Elapsed time since start_time
        """
        print(f"\nRUNNING ATTACK: Brute Force (Target: {target_username})")

        return brute_force_attack(server_url, target_username, endpoint=endpoint, start_time=start_time)
    
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
            # Start scenario timer
            scenario_start_time = time.time()

            # Set server URL
            server_url = f"{const.SERVER_HOST}:{const.SERVER_PORT}"

            # Get all usernames
            usernames = self.get_usernames_from_data()

            # Run attacks based on type
            elapsed_time = self.run_password_spraying_attack(server_url, usernames, start_time=scenario_start_time)
            self.rename_log_file(const.ATTACK_PASSWORD_SPRAYING)

            # Restart server for new attack type
            self.stop_server()
            self.start_server(config)

            # Reset database between attack types for clean state
            self.reset_database()

            # Run brute force on one user from each category
            brute_force_targets = self.get_brute_force_targets_by_category()
            print(brute_force_targets)
            for target_user in brute_force_targets:
                # Always use /login endpoint (TOTP is handled in defense response)
                elapsed_time = self.run_brute_force_attack(
                    server_url,
                    target_user,
                    endpoint=const.DEFAULT_ENDPOINT,
                    start_time=scenario_start_time
                )
            self.rename_log_file(const.ATTACK_BRUTE_FORCE)
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
            self.run_with_config(scenario["config"], run_server=True)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Attack simulator for testing authentication server defenses"
    )
    
    # Hash mode argument
    parser.add_argument(
        "--hash",
        type=str,
        choices=[const.SHA256_HASHING, const.BCRYPT_HASHING, const.ARGON2ID_HASHING],
        default=const.SHA256_HASHING,
        help="Password hashing algorithm to use (default: sha256)"
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
