# Design Document

## System Overview

```
+-------------+         HTTP          +-------------+
|             |  ------------------>  |             |
|  attacker   |  /login, /register    |   server    |
|   (CLI)     |  <------------------  |  (FastAPI)  |
|             |    JSON response      |             |
+-------------+                       +-------------+
                                            |
                                            | writes
                                            v
                                    +---------------+
                                    | attempts.log  |
                                    | (JSON lines)  |
                                    +---------------+

+-------------+
|  simulator  |  Orchestrates server + attacker
|   (CLI)     |  Runs experiments, generates summary
+-------------+
```

## Components

### 1. server.py (Headless CLI)

Authentication server with configurable hash modes and defenses.

Endpoints:
- POST /register - Create new user
- POST /login - Authenticate user
- POST /login_totp - Authenticate with TOTP

CLI flags:
```
--hash <mode>       sha256 | bcrypt | argon2id (default: sha256)
--rate-limit        Enable rate limiting
--lockout           Enable account lockout
--captcha           Enable CAPTCHA simulation
--totp              Enable TOTP requirement
--pepper            Enable pepper
--port <num>        Server port (default: 8000)
```

Config is also saved/loaded from server_config.json for persistence. <br>
CLI flags define explicit experiment configurations and update the stored config.

| CLI Arguments | Hash Mode | Defenses | Config Update |
|---------------|-----------|----------|---------------|
| `python server.py` | From config | From config | No change (uses stored config) |
| `python server.py --hash sha256` | sha256 | All disabled | Hash updated, defenses cleared |
| `python server.py --hash bcrypt --pepper` | bcrypt | Only pepper enabled | Both updated explicitly |
| `python server.py --pepper --rate-limit` | From config | Only specified enabled | Defenses updated, hash kept |
| `python server.py --port 9000` | From config | From config | Only port updated |


### 2. attacker.py (Headless CLI)

Attack simulator for brute-force and password-spraying.

CLI flags:
```
--target <url>      Server URL (default: http://localhost:8000)
--attack <type>     brute_force | spray
--user <username>   Target user (for brute_force)
--wordlist <file>   Password list file
--max-attempts <n>  Limit attempts (default: 50000)
```

### 3. simulator.py (Interactive CLI)

Menu-driven interface to run experiments.

```
Main Menu
---------
1. Server Management
2. Run Attack
3. Run Full Experiment Suite
4. Exit

Server Management
-----------------
1. Start Server
2. Stop Server
3. Configure Hash Mode
4. Configure Defenses
5. Back

Run Attack
----------
1. Brute-Force Attack
2. Password-Spray Attack
3. Back
```

## Data Flow

### Manual Attack (Menu options 1 + 2)

```
1. User configures server (hash + defenses)
2. User starts server
3. User runs attack (brute_force or spray)
4. Server logs each attempt to:
   src/logs/attempts/attempts_<hash>_<defenses>.log
5. Attack ends, simulator renames log to:
   attempts_<hash>_<defenses>_<attack_type>.log
```

### Full Experiment Suite (Menu option 3)

```
1. User selects "Run Full Experiment Suite"
2. Simulator loops through all combinations:
   For each hash mode (sha256, bcrypt, argon2id):
     For each defense combination:
       For each attack type (brute_force, spray):
         a. Simulator starts server with config
         b. Simulator runs attacker
         c. Server logs attempts
         d. Simulator renames log with attack type
         e. Simulator stops server
3. Simulator generates summary.csv from all logs
4. Done
```

## Log Format

### attempts.log (JSON lines)

Location: src/logs/attempts/attempts_<hash>_<defenses>_<attack>.log

Example filename: attempts_bcrypt_ratelimit_pepper_bruteforce.log

Fields per line:
```
{
  "timestamp": "2024-12-09T15:30:45.123Z",
  "username": "user01",
  "hash_mode": "bcrypt",
  "protection_flags": {
    "rate_limit": true,
    "lockout": false,
    "captcha": false,
    "totp": false,
    "pepper": true
  },
  "result": "failure",
  "latency_ms": 245,
  "group_seed": "519933725"
}
```

### summary.csv

Location: src/logs/summary/summary.csv

Columns:
```
hash_mode, rate_limit, lockout, captcha, totp, pepper, attack_type,
total_attempts, attempts_per_second, time_to_first_success,
average_latency_ms, success_rate_weak, success_rate_medium,
success_rate_strong, group_seed
```

Example row:
```
bcrypt,true,false,false,false,true,brute_force,1523,12.4,122.5,243,0.8,0.2,0.0,519933725
```

## users.json Format

Location: src/data/users.json

```
{
  "users": [
    {
      "username": "user01",
      "password": "123456",
      "category": "weak",
      "totp_secret": "JBSWY3DPEHPK3PXP"
    },
    {
      "username": "user02",
      "password": "MyD0g&Cat!",
      "category": "medium",
      "totp_secret": "KBSWY3DPEHPK3PXQ"
    }
  ],
  "group_seed": "519933725"
}
```

Categories:
- weak: 10 users (common passwords, short, dictionary words)
- medium: 10 users (some complexity, predictable patterns)
- strong: 10 users (random, long, mixed characters)

## Database

Location: src/server/db/

SQLite database storing user credentials and authentication state.

Files:
- auth.db - Main database with users table

## server_config.json Format

Location: src/server/config/server_config.json

```
{
  "host": "0.0.0.0",
  "port": 8000,
  "hash_mode": "bcrypt",
  "defenses": {
    "rate_limit": true,
    "lockout": false,
    "captcha": false,
    "totp": false,
    "pepper": true
  },
  "pepper_value": "secret_pepper_not_in_db",
  "group_seed": "519933725"
}
```

## Report Generation

Steps:
1. List all files in src/logs/attempts/
2. For each log file:
   - Parse filename for hash_mode, defenses, attack_type
   - Read JSON lines
   - Join with users.json to get password category
   - Calculate metrics:
      - total_attempts = count of lines
      - attempts_per_second = total / (last_timestamp - first_timestamp)
      - time_to_first_success = first success timestamp - first timestamp
      - average_latency_ms = mean of latency_ms
      - success_rate_by_category = successes / attempts per category
3. Append row to summary.csv
